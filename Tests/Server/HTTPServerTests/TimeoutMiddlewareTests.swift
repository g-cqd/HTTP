//
//  TimeoutMiddlewareTests.swift
//  HTTPServerTests
//
//  RFC 9110 §15.6.5 — the per-request deadline: a responder that finishes in time passes through, one
//  that overruns yields `504 Gateway Timeout` (problem+json), and the middleware sets
//  ``RequestContext/deadline`` for downstream handlers. The overrun case uses a tiny timeout against a
//  long, cancellable responder sleep, so the timeout always wins and the responder unwinds promptly.
//

import HTTPCore
import HTTPServer
import Testing

@Suite("Middleware — per-request timeout (504)")
struct TimeoutMiddlewareTests {
    private func get() -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
    }

    @Test("a responder that finishes within the deadline is returned untouched")
    func withinDeadline() async {
        let app = ClosureResponder { _, _, _ in .text("fast") }
        let responder = app.wrapped(by: TimeoutMiddleware(.seconds(10)))
        let response = await responder.respond(to: get(), body: [])
        #expect(response.head.status == .ok)
        #expect(response.body == Array("fast".utf8))
    }

    @Test("a responder that overruns the deadline yields 504 problem+json")
    func exceedsDeadline() async {
        let app = ClosureResponder { _, _, _ in
            // Cancelled by the timeout long before this elapses; the `try?` swallows the cancellation.
            try? await Task.sleep(for: .seconds(60))
            return .text("late")
        }
        let responder = app.wrapped(by: TimeoutMiddleware(.milliseconds(50)))
        let response = await responder.respond(to: get(), body: [])
        #expect(response.head.status == .gatewayTimeout)
        #expect(response.head.headerFields[.contentType] == "application/problem+json")
    }

    @Test("the middleware sets context.deadline for downstream handlers")
    func setsDeadline() async {
        let app = ClosureResponder { _, _, context in
            .text(context.deadline != nil ? "deadline-set" : "no-deadline")
        }
        let responder = app.wrapped(by: TimeoutMiddleware(.seconds(10)))
        let response = await responder.respond(to: get(), body: [])
        #expect(response.body == Array("deadline-set".utf8))
    }
}
