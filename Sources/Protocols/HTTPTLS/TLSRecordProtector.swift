//
//  TLSRecordProtector.swift
//  HTTPTLS
//
//  RFC 8446 §5.2/§5.3 — one direction's record protection. Sealing builds the
//  `TLSInnerPlaintext` (content ∥ type ∥ zero padding, §5.4) in fixed scratch, forms the nonce
//  as `write_iv XOR padded sequence` (§5.3), and AEAD-protects with the 5-octet record header
//  as additional data; opening reverses it. All cryptography is swift-crypto's
//  (`AES.GCM`/`ChaChaPoly`).
//
//  Two invariants are absolute:
//    • UNIFORM deprotection failure — every open error is ``TLSRecordError/badRecordMac``
//      (§5.2), one catch, one case, no leaked distinction between tag/padding/shape failures.
//    • The sequence NEVER wraps — sealing and opening refuse at the §5.5 bound with
//      ``TLSRecordError/recordLimitReached``; ``needsKeyUpdate`` trips first so Phase 3b can
//      drive the §4.6.3 KeyUpdate via ``ratchet()`` (§7.2) with margin to spare.
//

public import Crypto

internal import struct Foundation.Data

/// One direction's §5.2 record protection: seal/open, §5.3 nonces, §5.5 limits, §7.2 ratchet.
public struct TLSRecordProtector {
    /// How many records before ``needsKeyUpdate`` trips — a 2^16-record margin under the §5.5
    /// hard bound so a KeyUpdate flight has room to complete.
    static let keyUpdateMargin: UInt64 = 65_536

    /// The suite whose AEAD and geometry protect this direction.
    public let suite: TLSCipherSuite
    /// The live traffic secret (retained solely to feed the §7.2 ratchet).
    private var trafficSecret: SymmetricKey
    /// The §7.3 key/IV pair derived from ``trafficSecret``.
    private var keys: TLSTrafficKeys
    /// The reused 12-octet §5.3 nonce buffer (`write_iv XOR sequence`, rebuilt per record).
    private var nonceScratch: [UInt8]
    /// The reused §5.4 `TLSInnerPlaintext` assembly buffer (capacity fixed at init).
    private var innerScratch: [UInt8]
    /// The reused 5-octet header buffer (the AEAD's additional data, §5.2).
    private var headerScratch: [UInt8]
    /// The next record's sequence number (§5.3; starts at 0 on every key change).
    ///
    /// Internally settable so the §5.5 limit behavior is testable without 2^24 seals.
    public internal(set) var sequenceNumber: UInt64 = 0
    /// How many §7.2 ratchets this direction has taken (generation 0 = the installed secret).
    public private(set) var generation = 0

    /// Derives a direction's protection state from its §7.1 traffic secret.
    public init(suite: TLSCipherSuite, trafficSecret: SymmetricKey) {
        self.suite = suite
        self.trafficSecret = trafficSecret
        keys = TLSTrafficKeys(suite: suite, trafficSecret: trafficSecret)
        nonceScratch = [UInt8](repeating: 0, count: suite.ivLength)
        innerScratch = []
        innerScratch.reserveCapacity(TLSRecordLimits.maxInnerPlaintextLength)
        headerScratch = [UInt8](repeating: 0, count: TLSRecordLimits.headerLength)
    }

    /// Whether this direction is close enough to the §5.5 limit that the peer must be asked to
    /// rekey (Phase 3b sends KeyUpdate and calls ``ratchet()``).
    public var needsKeyUpdate: Bool {
        sequenceNumber >= suite.protectionSoftLimit - Self.keyUpdateMargin
    }

    /// §7.2's KeyUpdate ratchet: `traffic_secret_N+1 = HKDF-Expand-Label(traffic_secret_N,
    /// "traffic upd", …)`; fresh keys, sequence back to 0, old secret dropped.
    public mutating func ratchet() {
        trafficSecret = TLSKeySchedule.nextTrafficSecret(after: trafficSecret, hash: suite.hash)
        keys = TLSTrafficKeys(suite: suite, trafficSecret: trafficSecret)
        sequenceNumber = 0
        generation += 1
    }

    // MARK: Seal (§5.2 protect)

    /// Seals one record: appends header ∥ AEAD(content ∥ type ∥ padding) to `out` (§5.2–§5.4).
    ///
    /// - Parameters:
    ///   - type: The real content type, carried as the §5.4 inner type octet.
    ///   - fragment: The content (≤ 2^14 octets — the caller fragments).
    ///   - paddedLength: Round the inner plaintext up to this many octets with §5.4 zero
    ///     padding (clamped to the §5.2 cap; pass 0 for no padding).
    ///   - out: The outbound byte queue the record is appended to.
    /// - Throws: ``TLSRecordError/oversizeFragment``, ``TLSRecordError/recordLimitReached``
    ///   (§5.5 — never wraps), or ``TLSRecordError/sealFailed``.
    public mutating func seal(
        type: TLSContentType,
        fragment: ArraySlice<UInt8>,
        paddedLength: Int = 0,
        into out: inout [UInt8]
    ) throws(TLSRecordError) {
        guard fragment.count <= TLSRecordLimits.maxPlaintextLength else {
            throw .oversizeFragment
        }
        guard sequenceNumber < suite.protectionSoftLimit else {
            throw .recordLimitReached  // §5.5: rekey or terminate — never continue, never wrap
        }
        innerScratch.removeAll(keepingCapacity: true)
        innerScratch.append(contentsOf: fragment)
        innerScratch.append(type.rawValue)
        let target = min(
            max(paddedLength, innerScratch.count), TLSRecordLimits.maxInnerPlaintextLength
        )
        while innerScratch.count < target {
            innerScratch.append(0)  // §5.4 zeros after the inner content type
        }
        let bodyLength = innerScratch.count + suite.tagLength
        headerScratch[0] = TLSContentType.applicationData.rawValue  // §5.2 opaque_type
        headerScratch[1] = TLSRecordLimits.legacyVersionMajor
        headerScratch[2] = TLSRecordLimits.legacyVersionMinor
        headerScratch[3] = UInt8(truncatingIfNeeded: bodyLength >> 8)
        headerScratch[4] = UInt8(truncatingIfNeeded: bodyLength)
        buildNonce()
        let sealed: (ciphertext: Data, tag: Data)
        do {
            sealed = try sealAEAD()
        }
        catch {
            throw .sealFailed  // unreachable with §7.3 geometry; never force-try
        }
        out.append(contentsOf: headerScratch)
        out.append(contentsOf: sealed.ciphertext)
        out.append(contentsOf: sealed.tag)
        sequenceNumber += 1
    }

    // MARK: Open (§5.2 deprotect)

    /// Opens one protected record body (everything after the 5-octet header) and returns the
    /// inner content type and content — or the SINGLE uniform ``TLSRecordError/badRecordMac``.
    ///
    /// - Parameters:
    ///   - header: The record header exactly as received (the AEAD's additional data, §5.2).
    ///   - body: The `encrypted_record` octets.
    /// - Returns: The §5.4 inner content type and the content octets with padding stripped.
    /// - Throws: ``TLSRecordError/badRecordMac`` for EVERY deprotection failure (§5.2),
    ///   ``TLSRecordError/recordOverflow`` for either §5.2 length cap,
    ///   ``TLSRecordError/missingContentType``/``TLSRecordError/unknownContentType(_:)`` for a
    ///   §5.4 inner-type violation, or ``TLSRecordError/recordLimitReached`` at the §5.5 bound.
    public mutating func open(
        header: ArraySlice<UInt8>, body: ArraySlice<UInt8>
    ) throws(TLSRecordError) -> (type: TLSContentType, content: [UInt8]) {
        guard body.count <= TLSRecordLimits.maxCiphertextLength else {
            throw .recordOverflow  // §5.2 length cap
        }
        guard sequenceNumber < suite.protectionSoftLimit else {
            throw .recordLimitReached  // §5.5 — the peer must have rekeyed by now
        }
        // §5.2 UNIFORMITY: a too-short body, a bad tag, and bad padding all land in the one
        // `badRecordMac` case below — nothing before the AEAD call distinguishes shapes either.
        guard body.count >= suite.tagLength + 1 else {
            throw .badRecordMac
        }
        buildNonce()
        let plaintext: Data
        do {
            plaintext = try openAEAD(header: header, body: body)
        }
        catch {
            throw .badRecordMac  // §5.2: every deprotection failure is bad_record_mac
        }
        guard plaintext.count <= TLSRecordLimits.maxInnerPlaintextLength else {
            throw .recordOverflow  // §5.2: inner plaintext longer than 2^14 + 1
        }
        // §5.4: scan back across the zero padding for the inner content type octet.
        guard let typeIndex = plaintext.lastIndex(where: { $0 != 0 }) else {
            throw .missingContentType  // §5.4: no non-zero octet → unexpected_message
        }
        guard let innerType = TLSContentType(rawValue: plaintext[typeIndex]) else {
            throw .unknownContentType(plaintext[typeIndex])
        }
        sequenceNumber += 1
        return (innerType, [UInt8](plaintext[plaintext.startIndex ..< typeIndex]))
    }

    // MARK: AEAD dispatch (swift-crypto primitives only)

    /// §5.3: `nonce = write_iv XOR (0-padded big-endian sequence)`, built into fixed scratch.
    private mutating func buildNonce() {
        let ivOffset = suite.ivLength - 8
        for index in 0 ..< suite.ivLength {
            nonceScratch[index] = keys.ivBytes[index]
        }
        for index in 0 ..< 8 {
            let shift = UInt64(56 - index * 8)
            nonceScratch[ivOffset + index] ^= UInt8(truncatingIfNeeded: sequenceNumber >> shift)
        }
    }

    /// Runs the suite's AEAD over the assembled scratch (seal side).
    private func sealAEAD() throws -> (ciphertext: Data, tag: Data) {
        switch suite {
            case .aes128GcmSha256, .aes256GcmSha384:
                let box = try AES.GCM.seal(
                    innerScratch,
                    using: keys.key,
                    nonce: AES.GCM.Nonce(data: nonceScratch),
                    authenticating: headerScratch
                )
                return (box.ciphertext, box.tag)
            case .chaCha20Poly1305Sha256:
                let box = try ChaChaPoly.seal(
                    innerScratch,
                    using: keys.key,
                    nonce: ChaChaPoly.Nonce(data: nonceScratch),
                    authenticating: headerScratch
                )
                return (box.ciphertext, box.tag)
        }
    }

    /// Runs the suite's AEAD over a received body (open side).
    private func openAEAD(header: ArraySlice<UInt8>, body: ArraySlice<UInt8>) throws -> Data {
        let ciphertext = body.dropLast(suite.tagLength)
        let tag = body.suffix(suite.tagLength)
        switch suite {
            case .aes128GcmSha256, .aes256GcmSha384:
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonceScratch), ciphertext: ciphertext, tag: tag
                )
                return try AES.GCM.open(box, using: keys.key, authenticating: header)
            case .chaCha20Poly1305Sha256:
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonceScratch), ciphertext: ciphertext, tag: tag
                )
                return try ChaChaPoly.open(box, using: keys.key, authenticating: header)
        }
    }
}
