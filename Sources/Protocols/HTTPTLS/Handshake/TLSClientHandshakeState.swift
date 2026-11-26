//
//  TLSClientHandshakeState.swift
//  HTTPTLS
//
//  RFC 8446 §A.1 — the client handshake state machine ladder.
//

/// The state of a ``TLSClientConnection`` (RFC 8446 §A.1).
public enum TLSClientHandshakeState: Sendable, Equatable {
    /// Initial state before ``TLSClientConnection/start()`` emits `ClientHello`.
    case idle
    /// `ClientHello` emitted; awaiting `ServerHello` (or `HelloRetryRequest`).
    case expectingServerHello
    /// `HelloRetryRequest` processed and retried `ClientHello` emitted; awaiting `ServerHello`.
    case expectingRetriedServerHello
    /// `ServerHello` processed and handshake keys installed; awaiting `EncryptedExtensions`.
    case expectingEncryptedExtensions
    /// `EncryptedExtensions` processed; awaiting `CertificateRequest` or `Certificate`.
    case expectingServerCertificateOrRequest
    /// `CertificateRequest` received; awaiting server `Certificate`.
    case expectingServerCertificate
    /// Server `Certificate` validated; awaiting `CertificateVerify`.
    case expectingServerCertificateVerify
    /// Server `CertificateVerify` verified; awaiting server `Finished`.
    case expectingServerFinished
    /// Handshake complete; application data flows in both directions.
    case connected
    /// Terminal closed / aborted state.
    case closed

    /// Whether a handshake message of `type` is legal in this state (RFC 8446 §A.1).
    func accepts(_ type: TLSHandshakeType) -> Bool {
        switch self {
            case .expectingServerHello, .expectingRetriedServerHello:
                type == .serverHello
            case .expectingEncryptedExtensions:
                type == .encryptedExtensions
            case .expectingServerCertificateOrRequest:
                type == .certificate || type == .certificateRequest
            case .expectingServerCertificate:
                type == .certificate
            case .expectingServerCertificateVerify:
                type == .certificateVerify
            case .expectingServerFinished:
                type == .finished
            case .connected:
                type == .newSessionTicket || type == .keyUpdate
            case .idle, .closed:
                false
        }
    }
}
