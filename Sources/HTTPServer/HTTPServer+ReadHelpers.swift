//
//  HTTPServer+ReadHelpers.swift
//  HTTPServer
//
//  Read-loop helpers split out of HTTPServer.swift so that file stays focused on the accept/serve pump:
//  the per-phase receive deadline (Slowloris knobs, RFC 9112 §9.3) and the `Expect: 100-continue`
//  handshake (RFC 9110 §10.1.1).
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// The deadline for the next receive, chosen by request phase (the ``HTTPLimits`` Slowloris knobs).
    func receiveTimeout(
        _ buffer: [UInt8],
        headersParsed: Bool,
        _ headerDeadline: inout C.Instant?
    ) -> Duration {
        if buffer.isEmpty {
            return limits.keepAliveTimeout  // idle, awaiting the next request
        }
        if headersParsed {
            return limits.idleTimeout  // body phase
        }
        let deadline = headerDeadline ?? clock.now.advanced(by: limits.headerReadTimeout)
        headerDeadline = deadline  // cumulative across the whole header section
        return max(.zero, clock.now.duration(to: deadline))
    }

    /// Honors `Expect` before the body is read (RFC 9110 §10.1.1).
    ///
    /// Sends an interim `100 Continue` when the client awaits one, or a `417 Expectation Failed` for an
    /// unsupported expectation. Returns `true` iff a 417 was sent, so the caller closes the connection.
    func handleExpect(_ head: RequestHead, on connection: any TransportConnection) async -> Bool {
        switch ExpectDisposition.evaluate(head) {
            case .proceed:
                return false
            case .sendContinue:
                try? await connection.send(ExpectDisposition.continueLine)
                return false
            case .failed:
                try? await connection.send(
                    ResponseSerializer.serialize(HTTPResponse(status: .expectationFailed))
                )
                return true
        }
    }
}
