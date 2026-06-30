//
//  HTTPProtocolErrorTests.swift
//  HTTPServerTests
//
//  Phase 3.4 — the unified ``HTTPProtocolError`` seam: an HTTP/1.1, HTTP/2, and HTTP/3 error are each
//  catchable as `any HTTPProtocolError`, reporting their version, a diagnostic, and the connection-vs-
//  stream scope without switching on the three concrete types.
//

import HTTP1
import HTTP2
import HTTP3
import HTTPCore
import Testing

@Suite("Phase 3.4 — unified HTTPProtocolError")
struct HTTPProtocolErrorTests {
    @Test("each version's error is catchable as any HTTPProtocolError, reporting its version")
    func unifiedCatch() {
        let errors: [any HTTPProtocolError] = [
            HTTP1ParseError.bodyTooLarge,
            HTTP2Error.connection(.protocolError, "bad preface"),
            HTTP3Error.connection(.h3FrameUnexpected, "control frame on a request stream")
        ]
        let versions = errors.map(\.httpProtocol)
        #expect(versions == [.http1, .http2, .http3])
        // All three are connection-scoped here.
        #expect(errors[0].isConnectionError)
        #expect(errors[1].isConnectionError)
        #expect(errors[2].isConnectionError)
        #expect(errors[0].reason == "bodyTooLarge")
        #expect(errors[2].reason == "control frame on a request stream")
    }

    @Test("a stream-scoped HTTP/2 error reports isConnectionError == false")
    func streamScoped() {
        let error: any HTTPProtocolError =
            HTTP2Error.stream(HTTP2StreamID(1), .streamClosed, "late")
        #expect(error.httpProtocol == .http2)
        #expect(!error.isConnectionError)
        #expect(error.reason == "late")
    }

    @Test("the protocol version's raw value is the wire name")
    func versionWireNames() {
        #expect(HTTPProtocolVersion.http1.rawValue == "HTTP/1.1")
        #expect(HTTPProtocolVersion.http2.rawValue == "HTTP/2")
        #expect(HTTPProtocolVersion.http3.rawValue == "HTTP/3")
    }
}
