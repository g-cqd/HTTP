//
//  TLSChainVerdict.swift
//  HTTPTLS
//
//  The outcome currency of client-chain validation (Phase 3c). A rejection carries WHY, so
//  the engine can send the §6.2 alert RFC 8446 assigns to the failure class instead of a
//  generic `bad_certificate`: `unknown_ca` when "the CA certificate could not be located or
//  could not be matched with a known trust anchor", `certificate_expired` when "a
//  certificate has expired or is not currently valid", `bad_certificate` for the corrupt/
//  otherwise-unusable rest.
//

/// The outcome of validating a presented client-certificate chain (RFC 5280 §6).
public enum TLSChainVerdict: Sendable, Equatable {
    /// Why a chain was rejected — each case names its RFC 8446 §6.2 alert.
    public enum Rejection: Sendable, Equatable {
        /// No path to a configured trust anchor (§6.2 `unknown_ca`).
        case untrustedRoot
        /// The leaf is outside its RFC 5280 §4.1.2.5 validity window (§6.2
        /// `certificate_expired` — "expired or is not currently valid", so this also
        /// covers not-yet-valid).
        case expired
        /// Everything else — undecodable certificates, policy violations, a hook's veto
        /// (§6.2 `bad_certificate`). The label names the failure for logs; it never
        /// reaches the peer.
        case badCertificate(String)

        /// The §6.2 alert this rejection obliges the connection to send.
        public var alertDescription: TLSAlertDescription {
            switch self {
                case .untrustedRoot:
                    .unknownCA
                case .expired:
                    .certificateExpired
                case .badCertificate:
                    .badCertificate
            }
        }
    }

    /// The chain validates to a configured trust anchor under policy.
    case accepted
    /// The chain is rejected; the handshake dies with the rejection's alert.
    case rejected(Rejection)
}
