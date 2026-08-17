//
//  TLSServerHandshakeState.swift
//  HTTPTLS
//
//  RFC 8446 Appendix A.2 — the server's handshake state, linearized for a 0-RTT-rejecting,
//  sans-I/O server: START → (HRR loop, once) → the client-flight waits → CONNECTED, plus the
//  two terminal states every exit funnels into. WAIT_EOED never appears: this server always
//  declines early data, and a declined client MUST NOT send EndOfEarlyData (§4.2.10).
//

/// The server handshake state (RFC 8446 §A.2, adapted).
public enum TLSServerHandshakeState: Sendable, Equatable {
    /// A.2 START: awaiting the first ClientHello.
    case expectingClientHello
    /// A.2's `RecvClientHello ... send HelloRetryRequest` loop — taken at most once (§4.1.4:
    /// a second HelloRetryRequest is forbidden); awaiting the retried ClientHello.
    case expectingRetriedClientHello
    /// A.2 WAIT_CERT: our flight is out with a CertificateRequest; awaiting the client
    /// Certificate.
    case expectingClientCertificate
    /// A.2 WAIT_CV: a non-empty client Certificate arrived; awaiting CertificateVerify.
    case expectingClientCertificateVerify
    /// A.2 WAIT_FINISHED: awaiting the client Finished.
    case expectingClientFinished
    /// A.2 CONNECTED: the handshake is complete; application data and §4.6 post-handshake
    /// messages flow.
    case connected
    /// Terminal: `close_notify` passed (§6.1) in either direction.
    case closed
    /// Terminal: the one exit funnel ran — the alert (if owed) is queued, the error reported.
    case failed(TLSHandshakeError)

    /// Whether the connection reached a terminal state.
    public var isTerminal: Bool {
        switch self {
            case .closed, .failed:
                true
            default:
                false
        }
    }
}
