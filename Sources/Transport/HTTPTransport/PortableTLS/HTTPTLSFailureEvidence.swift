//
//  HTTPTLSFailureEvidence.swift
//  HTTPTransport
//
//  Phase 3d — what a fatal engine call knew, on the HTTPTLS engine. The BoringSSL flavor
//  had to DRAIN a per-thread error queue at the instant of classification because the
//  evidence would not keep; this engine's failures are typed values (`TLSHandshakeError`,
//  already carrying the §6 alert it sent), so the capture is trivial — but the REPORT
//  format the field greps for is load-bearing, so the description keeps the historical
//  prefix byte-for-byte: `SSL_read error 1 [connection N …]`. The `1` is `SSL_ERROR_SSL`'s
//  value — "the operation failed within the library" — which is exactly what a funneled
//  handshake error is; behind the prefix, the queue-dump gives way to the alert and the
//  typed reason, which is strictly more than the queue ever said.
//
//  The type name matches the BoringSSL flavor's on purpose: the two are build-exclusive
//  (`HTTP_PORTABLE_TLS` vs `HTTP_BORINGSSL_TLS`) and the engine's `Outcome.failed` carries
//  whichever one the build selected.
//

#if HTTP_PORTABLE_TLS_SWIFT

    internal import HTTPTLS

    /// The evidence pinned when an engine call came back fatal on the HTTPTLS engine.
    struct TLSFailureEvidence: Sendable, CustomStringConvertible {
        /// The classified entry point that failed: `SSL_accept`, `SSL_read`, or `SSL_write`
        /// — the historical spellings, kept so existing greps still match.
        let call: StaticString
        /// The connection the engine was constructed for — the identity the original field
        /// report lacked.
        let connectionID: TransportConnectionID
        /// The funneled machine error — typed, and already mapped to the §6 alert the peer
        /// was sent (RFC 8446 §6.2).
        let error: TLSHandshakeError

        /// Opens with the exact prefix the original field report captured
        /// (`SSL_read error 1`), then the identity and the typed cause.
        var description: String {
            let alert =
                error.alertDescription.map { "alert \($0.rawValue)" } ?? "no alert owed"
            return "\(call) error 1 "
                + "[connection \(connectionID.rawValue) \(alert) reason \(error)]"
        }
    }

#endif
