//
//  TLSHandshakeError.swift
//  HTTPTLS
//
//  The typed failure vocabulary of the handshake machine — the one funnel's currency. Every
//  fatal path throws exactly one of these; ``alertDescription`` names the RFC 8446 §6 alert the
//  connection sends before dying (nil when §6.2 forbids answering, i.e. after the PEER's error
//  alert). The record layer's own vocabulary is carried, not translated, in ``record(_:)`` so
//  no §5 distinction is lost on the way up.
//

/// A handshake failure (RFC 8446 §4/§6): typed, fatal, and mapped to its outgoing alert.
public enum TLSHandshakeError: Error, Sendable, Equatable {
    /// A record-layer failure surfaced through the machine (§5; carries its own alert).
    case record(TLSRecordError)
    /// A handshake message that could not be decoded — truncated field, bad internal length,
    /// or trailing octets (§6.2 `decode_error`). The label names the offending construct.
    case malformed(String)
    /// A `HandshakeType` octet outside RFC 8446 §4's repertoire (§6.2 `unexpected_message`).
    case unknownHandshakeType(UInt8)
    /// A handshake message declared longer than the configured reassembly cap — flood
    /// protection; the §4 `uint24` bound alone would allow 16 MiB messages (`decode_error`).
    case messageTooLarge(declared: Int, limit: Int)
    /// A message type that §4's server state machine does not accept in the current state
    /// ("peers which receive a message ... in an unexpected order MUST abort ...
    /// with an 'unexpected_message' alert", §4).
    case unexpectedMessage(TLSHandshakeType)
    /// A record type interleaved inside a fragmented handshake message (§5.1: "Handshake
    /// messages MUST NOT be interleaved with other record types").
    case interleavedHandshake(TLSContentType)
    /// The same extension appeared twice in one block (§4.2: "There MUST NOT be more than one
    /// extension of the same type in a given extension block").
    case duplicateExtension(TLSExtensionType)
    /// A recognized extension in a message the §4.2 table does not permit it in
    /// (`illegal_parameter` per §4.2).
    case extensionNotPermitted(TLSExtensionType)
    /// `pre_shared_key` was present but not last (§4.2.11: "Servers MUST check that it is the
    /// last extension and otherwise fail the handshake with an 'illegal_parameter' alert").
    case preSharedKeyNotLast
    /// A §9.2-mandatory extension is absent from the ClientHello (`missing_extension`).
    case missingExtension(TLSExtensionType)
    /// No TLS 1.3 to negotiate: `supported_versions` absent (Appendix D.2 — a 1.3-only server
    /// "MUST abort the handshake with a 'protocol_version' alert"), 0x0304 not offered
    /// (§4.2.1), or `legacy_version` ≤ 0x0300 (Appendix D.5).
    case unsupportedVersion
    /// A field value RFC 8446 rules out — non-null compression (§4.1.2), a key share for a
    /// group absent from `supported_groups` (§4.2.8), an invalid public share (§4.2.8.2), a
    /// `record_size_limit` below 64 (RFC 8449 §4), an out-of-contract retry ClientHello
    /// (§4.1.2/§4.1.4), or a client CertificateVerify scheme outside our CertificateRequest
    /// offer (§4.4.3). The label names the parameter.
    case illegalParameter(String)
    /// No overlap in cipher suites, groups, or signature schemes (§4.1.1: failing to negotiate
    /// acceptable parameters is `handshake_failure`). The label names the empty intersection.
    case negotiationFailed(String)
    /// The client offered ALPN, this listener has an ALPN contract, and the intersection is
    /// empty (RFC 7301 §3.2 `no_application_protocol`).
    case noApplicationProtocol
    /// A PSK binder failed validation (§4.2.11.2: "if it is not present or does not validate,
    /// the server MUST abort the handshake" — `decrypt_error`).
    case invalidBinder
    /// A Finished whose verify_data is wrong (§4.4.4: "recipients ... MUST terminate the
    /// connection with a 'decrypt_error' alert if it is incorrect").
    case invalidFinished
    /// A CertificateVerify signature that does not verify over the transcript (§4.4.3: "if the
    /// verification fails, the receiver MUST terminate the handshake with a 'decrypt_error'").
    case invalidCertificateVerify
    /// Client authentication is `.required` and the client sent an empty Certificate
    /// (§4.4.2.4: the server MAY abort with a `certificate_required` alert — this engine does,
    /// fail closed, matching the portable TLS `.required` semantics).
    case certificateRequired
    /// The client's leaf certificate could not be used to verify its CertificateVerify — an
    /// unsupported signature scheme with no capable verifier configured
    /// (§6.2 `unsupported_certificate`; present-but-unverifiable is fatal even under
    /// `.optional`, matching the portable TLS fail-closed hook).
    case unverifiableCertificate(TLSSignatureScheme)
    /// The client's certificate message was structurally bad — undecodable DER, no leaf, or a
    /// nonempty `certificate_request_context` (§4.4.2 — `bad_certificate`).
    case badCertificate(String)
    /// A client Certificate entry carried an extension our CertificateRequest never offered
    /// (§4.4.2: "extensions in the Certificate message from the client MUST correspond to
    /// extensions in the CertificateRequest" — §6.2 `unsupported_extension`).
    case unrequestedCertificateExtension(TLSExtensionType)
    /// A KeyUpdate whose `request_update` is neither 0 nor 1 (§4.6.3: "MUST terminate the
    /// connection with an 'illegal_parameter' alert").
    case invalidKeyUpdate(UInt8)
    /// The configured ``TLSIdentityProvider`` failed to sign or returned a scheme outside the
    /// offered list — a local fault (§6.2 `internal_error`).
    case signingFailed
    /// A local invariant failed (key-ladder misuse, vault sealing) — §6.2 `internal_error`.
    case internalError(String)
    /// The peer sent an error alert; §6.2 forbids answering it ("MUST NOT send further data"),
    /// so this case maps to NO outgoing alert.
    case peerAlert(TLSAlert)
    /// The connection already reached a terminal state; no octets are processed and no alert
    /// is owed.
    case connectionClosed
    /// `issueSessionTicket()` was called with no ``TLSTicketVault`` configured — a caller
    /// error, deliberately NOT funneled (the connection stays usable, no alert).
    case sessionTicketsUnavailable

    /// The RFC 8446 §6 alert this failure obliges the connection to send before closing —
    /// nil when no alert may be sent (the peer already erred, or nothing is owed).
    public var alertDescription: TLSAlertDescription? {
        switch self {
            case .record(let recordError):
                recordError.alertDescription
            case .malformed, .messageTooLarge:
                .decodeError
            case .unknownHandshakeType, .unexpectedMessage, .interleavedHandshake:
                .unexpectedMessage
            case .duplicateExtension, .extensionNotPermitted, .preSharedKeyNotLast,
                .illegalParameter, .invalidKeyUpdate:
                .illegalParameter
            case .missingExtension:
                .missingExtension
            case .unsupportedVersion:
                .protocolVersion
            case .negotiationFailed:
                .handshakeFailure
            case .noApplicationProtocol:
                .noApplicationProtocol
            case .invalidBinder, .invalidFinished, .invalidCertificateVerify:
                .decryptError
            case .certificateRequired:
                .certificateRequired
            case .unverifiableCertificate:
                .unsupportedCertificate
            case .badCertificate:
                .badCertificate
            case .unrequestedCertificateExtension:
                .unsupportedExtension
            case .signingFailed, .internalError:
                .internalError
            case .peerAlert, .connectionClosed, .sessionTicketsUnavailable:
                nil
        }
    }
}
