//
//  MetricsMiddlewareTests.swift
//  HTTPServerTests
//
//  The observability seam: MetricsMiddleware records exactly one metric per response, carrying the
//  request method/path, the response status, and the duration measured against its injected clock.
//  A deterministic ManualClock (advanced by the handler) lets the duration be asserted exactly, so a
//  swapped subtraction (negative) or a hard-coded zero is caught — not just "non-negative".
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("MetricsMiddleware — the per-response observability seam")
struct MetricsMiddlewareTests {
    @Test("records the method, path, status, and measured duration of a response")
    func recordsResponse() async {
        let spy = SpyMetrics()
        let clock = ManualClock()
        let app = ClosureResponder { _, _ in
            clock.advance(by: .milliseconds(7))  // the handler "takes" 7 ms
            return ServerResponse(HTTPResponse(status: .created))
        }
        let responder = app.wrapped(by: MetricsMiddleware(spy, clock: clock))

        let request = HTTPRequest(method: .post, scheme: "https", authority: "x", path: "/items")
        _ = await responder.respond(to: request, body: [])

        let records = spy.records
        #expect(records.count == 1)
        #expect(records.first?.method == .post)
        #expect(records.first?.path == "/items")
        #expect(records.first?.status == .created)
        #expect(records.first?.duration == .milliseconds(7))
    }

    @Test("records exactly one metric per response — the request rate")
    func recordsPerResponse() async {
        let spy = SpyMetrics()
        let app = ClosureResponder { _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let responder = app.wrapped(by: MetricsMiddleware(spy, clock: ManualClock()))

        for path in ["/a", "/b", "/c"] {
            let request = HTTPRequest(method: .get, scheme: "https", authority: "x", path: path)
            _ = await responder.respond(to: request, body: [])
        }

        #expect(spy.records.count == 3)
        #expect(spy.records.map(\.path) == ["/a", "/b", "/c"])
    }
}
