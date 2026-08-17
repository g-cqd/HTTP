//
//  TLSClientAuthenticationMode.swift
//  HTTPTLS
//
//  RFC 8446 §4.3.2/§4.4.2.4 — whether and how strictly this server requests a client
//  certificate. The semantics mirror the portable TLS backbone's `TransportTLS.ClientAuth`
//  exactly (its G3 fail-closed audit): absent is legal under `.optional`, fatal under
//  `.required` (`certificate_required`), and a PRESENT certificate is always verified — a
//  present-but-unverifiable certificate is fatal in every requesting mode.
//

/// The client-authentication policy (RFC 8446 §4.3.2/§4.4.2.4).
public enum TLSClientAuthenticationMode: Sendable, Equatable {
    /// No CertificateRequest is sent — one-way TLS (the default).
    case none
    /// A CertificateRequest is sent; an empty client Certificate is accepted (§4.4.2), but a
    /// presented certificate whose CertificateVerify fails is fatal (fail closed).
    case optional
    /// A CertificateRequest is sent; an empty client Certificate aborts with
    /// `certificate_required` (§4.4.2.4).
    case required

    /// Whether this mode emits a CertificateRequest (§4.3.2).
    public var requestsCertificate: Bool {
        self != .none
    }
}
