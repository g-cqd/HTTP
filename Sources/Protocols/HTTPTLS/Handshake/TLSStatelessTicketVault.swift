//
//  TLSStatelessTicketVault.swift
//  HTTPTLS
//
//  The default ``TLSTicketVault``: stateless, self-encrypted tickets (RFC 8446 §4.6.1's opaque
//  label over RFC 5077 §4's recommended construction, modernized to AEAD). A ticket is
//
//      key name (8) ∥ AES-GCM nonce (12) ∥ AES-256-GCM(state; AAD = key name) ∥ tag (16)
//
//  so the server keeps NO per-ticket state: redemption is name lookup + one decryption.
//  Rotation: seal under `keys.first`, open under whichever named key matches — callers rotate
//  by prepending a fresh ``TLSTicketKey``. Every open failure — alien name, wrong length, bad
//  tag, undecodable state, expiry — is the same nil (no oracle; the connection just declines
//  to resume, §4.2.11).
//

internal import Crypto

/// Stateless self-encrypted session tickets (RFC 8446 §4.6.1) under caller-provided keys.
public struct TLSStatelessTicketVault: TLSTicketVault {
    /// The state-encoding version octet (bump on layout change; old tickets then decline).
    private static let encodingVersion: UInt8 = 1
    /// The AES-GCM nonce length.
    private static let nonceLength = 12
    /// The AES-GCM tag length.
    private static let tagLength = 16

    /// The ticket keys — sealing uses the first; opening accepts any (rotation window).
    private let keys: [TLSTicketKey]

    /// Creates a vault over the caller's ticket keys; nil when no keys are supplied.
    public init?(keys: [TLSTicketKey]) {
        guard !keys.isEmpty else {
            return nil
        }
        self.keys = keys
    }

    /// Seals under the newest key: name ∥ nonce ∥ ciphertext ∥ tag.
    public func sealTicket(_ state: TLSResumptionState) throws -> [UInt8] {
        guard let key = keys.first else {
            throw TLSHandshakeError.internalError("empty ticket vault")
        }
        let sealed = try AES.GCM.seal(
            encode(state), using: key.secret, authenticating: key.name
        )
        var ticket = key.name
        ticket.reserveCapacity(
            TLSTicketKey.nameLength + Self.nonceLength + sealed.ciphertext.count
                + Self.tagLength
        )
        ticket.append(contentsOf: sealed.nonce)
        ticket.append(contentsOf: sealed.ciphertext)
        ticket.append(contentsOf: sealed.tag)
        return ticket
    }

    /// Opens any live ticket of ours; every failure mode is the same nil.
    public func openTicket(_ ticket: [UInt8], at now: UInt64) -> TLSResumptionState? {
        let minimum = TLSTicketKey.nameLength + Self.nonceLength + Self.tagLength + 1
        guard ticket.count >= minimum else {
            return nil
        }
        let name = [UInt8](ticket[..<TLSTicketKey.nameLength])
        guard let key = keys.first(where: { $0.name == name }) else {
            return nil
        }
        let nonceEnd = TLSTicketKey.nameLength + Self.nonceLength
        guard
            let nonce = try? AES.GCM.Nonce(data: ticket[TLSTicketKey.nameLength ..< nonceEnd]),
            let box = try? AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: ticket[nonceEnd ..< ticket.count - Self.tagLength],
                tag: ticket[(ticket.count - Self.tagLength)...]
            ),
            let plaintext = try? AES.GCM.open(box, using: key.secret, authenticating: name),
            let state = try? decode([UInt8](plaintext)),
            state.isLive(at: now)
        else {
            return nil
        }
        return state
    }

    /// Encodes the state plaintext (version ∥ hash ∥ issuedAt ∥ lifetime ∥ ageAdd ∥ psk ∥
    /// sni ∥ alpn; empty vectors mean absent).
    private func encode(_ state: TLSResumptionState) -> [UInt8] {
        var builder = TLSHandshakeBuilder()
        builder.u8(Self.encodingVersion)
        builder.u8(state.hash == .sha384 ? 1 : 0)
        builder.u32(UInt32(truncatingIfNeeded: state.issuedAt >> 32))
        builder.u32(UInt32(truncatingIfNeeded: state.issuedAt))
        builder.u32(state.lifetimeSeconds)
        builder.u32(state.ageAdd)
        // SAFETY: the PSK must ride inside the ticket plaintext; `SymmetricKey` exposes its
        // octets only through `withUnsafeBytes`, scoped to this one materialization (the
        // TLSTrafficKeys pattern) — the copy is immediately AEAD-sealed by the caller.
        let psk = unsafe state.preSharedKey.withUnsafeBytes { unsafe [UInt8]($0) }
        builder.vector8 { $0.raw(psk) }
        builder.vector16 { sni in
            if let serverName = state.serverName {
                sni.raw(serverName.utf8)
            }
        }
        builder.vector16 { alpn in
            if let alpnProtocol = state.alpnProtocol {
                alpn.raw(alpnProtocol.utf8)
            }
        }
        return builder.bytes
    }

    /// Decodes a state plaintext; throws on any shape defect (folded to nil by the caller).
    private func decode(_ plaintext: [UInt8]) throws(TLSHandshakeError) -> TLSResumptionState {
        var reader = TLSHandshakeReader(plaintext[...])
        guard try reader.byte("version") == Self.encodingVersion else {
            throw .malformed("ticket version")
        }
        let hash: TLSHashFunction = try reader.byte("hash") == 1 ? .sha384 : .sha256
        let issuedHigh = try reader.u32("issuedAt")
        let issuedLow = try reader.u32("issuedAt")
        let lifetime = try reader.u32("lifetime")
        let ageAdd = try reader.u32("ageAdd")
        let psk = try reader.vector8("psk")
        guard psk.count == hash.digestByteCount else {
            throw .malformed("ticket psk length")
        }
        let sni = try reader.vector16("sni")
        let alpn = try reader.vector16("alpn")
        try reader.expectEnd(of: "ticket state")
        return TLSResumptionState(
            preSharedKey: SymmetricKey(data: psk),
            hash: hash,
            issuedAt: UInt64(issuedHigh) << 32 | UInt64(issuedLow),
            lifetimeSeconds: lifetime,
            ageAdd: ageAdd,
            serverName: sni.isEmpty ? nil : String(validating: Array(sni), as: UTF8.self),
            alpnProtocol: alpn.isEmpty ? nil : String(validating: Array(alpn), as: UTF8.self)
        )
    }
}
