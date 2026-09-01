//
//  TimeoutMiddlewareTests.swift
//  HTTPServerTests
//
//  RFC 9110 §15.6.5 — the per-request deadline: a responder that finishes in time passes through, one
//  that overruns yields `504 Gateway Timeout` (problem+json), and the middleware sets
//  ``RequestContext/deadline`` for downstream handlers. The overrun case uses a tiny timeout against a
//  long, cancellable responder sleep, so the timeout always wins and the responder unwinds promptly.
//
//  Also locks in the 2026-07-31 audit's finding 17: the contract is COOPERATIVE — a responder that
//  ignores cancellation delays the 504 by its own runtime, which is a documented property rather than a
//  bug to be fixed with more task-group logic — and a nested deadline may only narrow, never widen.
//

import HTTPCore
import HTTPServer
internal import Synchronization
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

    /// The cooperative contract, made executable.
    ///
    /// A responder that never suspends cannot be cancelled, so the task group cannot return until it
    /// finishes — the middleware is structurally unable to answer early no matter how short the
    /// deadline. This asserts the elapsed time rather than the status because *which* branch wins is
    /// genuinely non-deterministic under load: if the busy-wait occupies the thread the timer task
    /// needed, the responder wins outright and the peer gets a 200 long after its deadline. Both
    /// outcomes are the same defect, and the timing is what proves it.
    @Test("a responder that ignores cancellation cannot be answered early")
    func cancellationIgnoringResponderDelaysTheAnswer() async {
        let burn = Duration.milliseconds(120)
        let started = ContinuousClock.now
        let app = ClosureResponder { _, _, _ in
            // Busy-wait: no suspension point, so cancellation cannot take effect.
            let until = ContinuousClock.now.advanced(by: burn)
            while ContinuousClock.now < until {
                continue
            }
            return .text("late")
        }
        let responder = app.wrapped(by: TimeoutMiddleware(.milliseconds(1)))
        _ = await responder.respond(to: get(), body: [])

        // The 1 ms deadline bought nothing: the answer could not arrive before the responder returned.
        #expect(started.duration(to: ContinuousClock.now) >= burn)
    }

    /// A nested timeout may only tighten the bound.
    ///
    /// Widening would let an inner middleware grant a handler more time than an outer one allowed,
    /// silently defeating the outer bound.
    @Test("a nested timeout narrows the deadline and never widens it")
    func nestedDeadlineOnlyNarrows() async {
        let seen = Mutex<ContinuousClock.Instant?>(nil)
        let app = ClosureResponder { _, _, context in
            seen.withLock { $0 = context.deadline }
            return .text("ok")
        }
        // The INNER middleware (applied last, so closest to the handler) asks for far longer.
        let responder =
            app
            .wrapped(by: TimeoutMiddleware(.seconds(60)))
            .wrapped(by: TimeoutMiddleware(.milliseconds(200)))
        _ = await responder.respond(to: get(), body: [])

        let deadline = seen.withLock(\.self)
        let remaining = deadline.map { ContinuousClock.now.duration(to: $0) }
        #expect(remaining != nil)
        #expect((remaining ?? .zero) <= .milliseconds(200))  // the outer, tighter bound survives
    }

    @Test("timeRemaining reports the gap, clamps to zero once past, and is nil when unbounded")
    func timeRemainingReportsTheGap() {
        let now = ContinuousClock.now
        var context = RequestContext()
        #expect(context.timeRemaining(now: now) == nil)

        context.deadline = now.advanced(by: .seconds(5))
        #expect(context.timeRemaining(now: now) == .seconds(5))

        context.deadline = now.advanced(by: .seconds(-5))
        #expect(context.timeRemaining(now: now) == .zero)  // never negative
    }
}
