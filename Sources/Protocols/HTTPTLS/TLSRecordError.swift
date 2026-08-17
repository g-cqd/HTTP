//
//  TLSRecordError.swift
//  HTTPTLS
//
//  The typed failure vocabulary of the record layer. Every malformed or out-of-place record is one
//  of these (never a trap), and each case maps to the RFC 8446 §6 alert the connection must send
//  before closing. §5.2's uniformity rule is honored by construction: EVERY deprotection failure —
//  tag, padding, nonce, or ciphertext shape — is the single ``badRecordMac`` case, so no
//  distinction between them can leak to the peer or to timing-adjacent driver code.
//

/// A record-layer failure (RFC 8446 §5/§6): typed, fatal, and mapped to its outgoing alert.
public enum TLSRecordError: Error, Sendable, Equatable {
    /// A record failed AEAD deprotection — the SINGLE §5.2 outcome for tag, padding, and every
    /// other decrypt failure, so nothing distinguishes them (`bad_record_mac` semantics).
    case badRecordMac
    /// A record exceeded the §5.1 (2^14) or §5.2 (2^14 + 256, and 2^14 + 1 inner) length caps.
    case recordOverflow
    /// A protected record's plaintext was all padding — no §5.4 inner content type octet.
    case missingContentType
    /// The outer or inner content type octet is not a known ``TLSContentType`` (§5.1/§5.2).
    case unknownContentType(UInt8)
    /// An unprotected record of this type is not acceptable at the current read epoch (§5.2:
    /// once keys are installed, only protected records — and tolerated CCS — may arrive).
    case unexpectedPlaintextRecord(TLSContentType)
    /// A protected record's inner content type is not acceptable at the current read epoch
    /// (e.g. application data before the handshake completed, or an encrypted CCS — §5).
    case unexpectedProtectedRecord(TLSContentType)
    /// A `change_cipher_spec` record outside the §5/D.4 tolerance window (before the first
    /// handshake record or after the read side reached the application epoch), or one whose
    /// body is not exactly the single octet 0x01.
    case unexpectedChangeCipherSpec
    /// An alert record that is not exactly one two-octet Alert (§6: never fragmented/coalesced).
    case malformedAlertRecord
    /// A zero-length handshake fragment, which §5.1 forbids peers to send.
    case emptyHandshakeRecord
    /// The per-direction sequence number or §5.5 record limit is exhausted — the connection MUST
    /// rekey or terminate; the record layer refuses to seal/open past the bound (never wraps).
    case recordLimitReached
    /// A key installation or ratchet that the §7 epoch ladder does not permit (wrong order,
    /// mismatched cipher suite, or a ratchet outside the application epoch).
    case invalidKeyInstallation
    /// An outbound fragment larger than the negotiated plaintext cap was submitted (§5.1).
    case oversizeFragment
    /// The AEAD refused to seal — unreachable with §7.3-derived key/nonce geometry, but
    /// swift-crypto's seal is throwing and this engine never force-tries (fail closed).
    case sealFailed

    /// The RFC 8446 §6 alert this failure obliges the connection to send before closing.
    public var alertDescription: TLSAlertDescription {
        switch self {
            case .badRecordMac:
                .badRecordMac
            case .recordOverflow:
                .recordOverflow
            case .missingContentType, .unexpectedPlaintextRecord, .unexpectedProtectedRecord,
                .unexpectedChangeCipherSpec, .emptyHandshakeRecord:
                .unexpectedMessage
            case .unknownContentType, .malformedAlertRecord:
                .decodeError
            case .recordLimitReached, .invalidKeyInstallation, .oversizeFragment, .sealFailed:
                .internalError
        }
    }
}
