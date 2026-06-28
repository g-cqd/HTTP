//
//  HTTPServer+ClientCert.swift
//  HTTPServer
//
//  Surfaces a mutual-TLS (G3) client identity to handlers the same way the rest of the stack surfaces
//  verified context (`RequestIDMiddleware`, `SessionMiddleware`, the auth middlewares): a
//  server-asserted header the request carries, never a breaking change to the responder protocol. The
//  transport captures the verified client-certificate subject at handshake `.ready`
//  (`TransportConnection.tlsPeerSubject`); the per-exchange dispatch path stamps it onto the request as
//  `X-Client-Cert-Subject` before the responder runs, stripping any inbound value so the handler only
//  ever sees a subject the server itself verified.
//

internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Returns `request` with the verified TLS client-certificate subject stamped as the
    /// server-asserted ``HTTPFieldName/xClientCertSubject``.
    ///
    /// Any inbound `X-Client-Cert-Subject` is stripped first (a client cannot spoof it), then the
    /// connection's verified subject — if mutual TLS presented one — is appended. The append routes
    /// through `HTTPField`'s `field-value` validation (RFC 9110 §5.5), so a hostile certificate whose
    /// subject embeds CR/LF cannot inject a header line (CWE-93): an invalid subject is simply dropped,
    /// leaving the field absent rather than forged. A connection with no client certificate yields the
    /// request with the field stripped and nothing added.
    static func stampingClientCertSubject(
        _ request: HTTPRequest,
        from connection: any TransportConnection
    ) -> HTTPRequest {
        stampingClientCertSubject(request, subject: connection.tlsPeerSubject)
    }

    /// Stamps `subject` (a verified TLS client-certificate subject, or `nil`) as the server-asserted
    /// ``HTTPFieldName/xClientCertSubject``, always stripping any inbound value first.
    ///
    /// The subject-taking peer of `stampingClientCertSubject(_:from:)`, for transports whose connection
    /// is not a ``TransportConnection`` — the HTTP/3 path passes ``QUICConnection/tlsPeerSubject``. The
    /// strip runs unconditionally, so a `nil` subject still removes a spoofed inbound header (a client
    /// cannot forge the field even when mutual TLS is off); CR/LF-bearing subjects are dropped by
    /// `HTTPField`'s `field-value` validation rather than forged (CWE-93).
    static func stampingClientCertSubject(
        _ request: HTTPRequest,
        subject: String?
    ) -> HTTPRequest {
        var request = request
        request.headerFields.removeAll(named: .xClientCertSubject)
        if let subject {
            _ = request.headerFields.append(subject, for: .xClientCertSubject)
        }
        return request
    }
}
