//
//  DeadlineRearmTests.swift
//  HTTPServerTests
//
//  PERF-1 / ADD-P2 (timer half) — the late-enforcement defect. `IdleDeadline.arm(_:)` only mutated
//  mutex-protected state, so a watchdog already parked in `clock.sleep(until:)` toward a LATER target
//  never woke early. A fast 60 s body read followed by a 15 s keep-alive budget was therefore enforced
//  ~45 s late: the Slowloris bound the operator configured (RFC 9112 §9.3; CWE-400, uncontrolled
//  resource consumption) simply did not hold. HTTP/3 had the same shape whenever a 10 s header deadline
//  was armed while the shared per-connection watchdog slept on a 60 s body deadline (RFC 9114 §4.1).
//
//  Proved deterministically against an injected ``TestClock``: the clock is advanced to exactly the
//  EARLIER instant and never past it, so a lapse observed here can only have come from enforcement at
//  the earlier deadline. No wall-clock timing participates in the assertion.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Deadline re-arm — an earlier target must wake a sleeping watchdog")
struct DeadlineRearmTests {
    /// The three deadline shapes the server arms, exercised through the one facility they share.
    ///
    /// Each names a real caller: `keepAlive` is the HTTP/1.1 serve loop's connection-wide budget
    /// (HTTPServer+RequestReader.swift), `send` is the HTTP/2 consumer's own send budget
    /// (HTTPServer+HTTP2.swift), `stream` is an HTTP/3 request stream's read budget
    /// (HTTPServer+HTTP3.swift).
    enum Shape: String, Sendable, CaseIterable {
        case keepAlive
        case send
        case stream
    }

    @Test(
        "an earlier re-arm is enforced at the earlier instant, not the later one",
        arguments: Shape.allCases)
    func earlierRearmIsEnforcedOnTime(shape: Shape) async throws {
        let clock = TestClock()
        let server = try Self.makeServer(clock: clock)
        let wheel = DeadlineWheel()
        let lapses = AsyncEventProbe<Duration>()
        let handle = wheel.register {
            lapses.record(clock.now.offset)
            return .keepWatching
        }

        // The long budget first — the body read that legitimately gets 60 s.
        wheel.arm(handle, until: server.deadlineKey(after: .seconds(60)))
        let watchdog = Task { await server.runDeadlineWatchdog(wheel) }
        defer { watchdog.cancel() }
        try await clock.waitForSleepers(atLeast: 1)  // parked on t=60

        // The short budget replaces it — the keep-alive/header/stream budget that must now bind.
        wheel.arm(handle, until: server.deadlineKey(after: .seconds(15)))
        clock.advance(by: .seconds(15))

        let observed = try await lapses.wait(forAtLeast: 1)
        // The clock never moved past 15 s, so this lapse cannot be the 60 s one arriving late.
        #expect(observed == [.seconds(15)], "\(shape.rawValue) was enforced late")
        #expect(clock.now.offset == .seconds(15))
    }

    @Test("a later re-arm does not fire early")
    func laterRearmDoesNotFireEarly() async throws {
        let clock = TestClock()
        let server = try Self.makeServer(clock: clock)
        let wheel = DeadlineWheel()
        let lapses = AsyncEventProbe<Duration>()
        let handle = wheel.register {
            lapses.record(clock.now.offset)
            return .keepWatching
        }

        wheel.arm(handle, until: server.deadlineKey(after: .seconds(15)))
        let watchdog = Task { await server.runDeadlineWatchdog(wheel) }
        defer { watchdog.cancel() }
        try await clock.waitForSleepers(atLeast: 1)

        // Progress: the read landed, so the budget is pushed out. Nothing may fire at the old target.
        wheel.arm(handle, until: server.deadlineKey(after: .seconds(60)))
        clock.advance(by: .seconds(30))
        try await Self.settle()
        #expect(lapses.isEmpty, "a pushed-out deadline fired at its old target")

        clock.advance(by: .seconds(30))
        let observed = try await lapses.wait(forAtLeast: 1)
        #expect(observed == [.seconds(60)])
    }

    @Test("a released handle cannot fire against the identity that reused its slot")
    func releaseInvalidatesTheEntry() async throws {
        let clock = TestClock()
        let server = try Self.makeServer(clock: clock)
        let wheel = DeadlineWheel()
        let stale = AsyncEventProbe<Duration>()
        let fresh = AsyncEventProbe<Duration>()

        let torndown = wheel.register {
            stale.record(clock.now.offset)
            return .keepWatching
        }
        wheel.arm(torndown, until: server.deadlineKey(after: .seconds(5)))
        let watchdog = Task { await server.runDeadlineWatchdog(wheel) }
        defer { watchdog.cancel() }
        try await clock.waitForSleepers(atLeast: 1)

        // Teardown, then a new connection lands on the recycled slot.
        wheel.release(torndown)
        let reused = wheel.register {
            fresh.record(clock.now.offset)
            return .keepWatching
        }
        #expect(reused.slot == torndown.slot, "the fixture needs the slot to be recycled")
        #expect(reused.generation != torndown.generation)

        // Every operation carrying the dead handle is a no-op against the live identity.
        wheel.arm(torndown, until: server.deadlineKey(after: .seconds(1)))
        wheel.disarm(reused)
        wheel.release(torndown)
        wheel.arm(reused, until: server.deadlineKey(after: .seconds(10)))

        clock.advance(by: .seconds(10))
        let observed = try await fresh.wait(forAtLeast: 1)
        #expect(observed == [.seconds(10)])
        #expect(stale.isEmpty, "a released handle fired against the identity that reused its slot")
    }

    /// Re-arming an already-armed handle must not allocate: it happens around every read, and at the
    /// 200k rps target a single malloc there is 200k mallocs/s of pure overhead.
    ///
    /// Asserted exactly in an optimized build, where the count means something. `-Onone` charges
    /// roughly two allocations to a *bare* `for handle in handles { _ = handle.slot }` loop, so a debug
    /// count measures the unoptimized calling convention rather than this data structure; what is still
    /// meaningful there is that the cost does not GROW with the number of re-arms, which is the
    /// property that separates an indexed heap from a push-stale-entries heap.
    @Test("re-arming an already-armed handle allocates nothing")
    func rearmIsAllocationFree() {
        guard allocationCountingAvailable else {
            return  // Darwin-only malloc hook; nothing to assert elsewhere
        }
        let wheel = DeadlineWheel()
        let handles = (0 ..< 64).map { _ in wheel.register { .keepWatching } }
        var target = Duration.zero
        // The heap and slot storage reach their steady-state capacity here, so every re-arm measured
        // below is pure in-place mutation.
        func rearmAll() {
            for handle in handles {
                target += .seconds(1)
                wheel.arm(handle, until: target)
            }
        }
        for _ in 0 ..< 4 {
            rearmAll()
        }

        let first = mallocDelta { rearmAll() }
        let second = mallocDelta { rearmAll() }
        #expect(first == second, "re-arm cost grows with the number of re-arms already performed")
        #if !DEBUG
            #expect(first == 0, "re-arm allocated \(first ?? -1) time(s) on the hot path")
        #endif
    }

    // MARK: - Fixtures

    /// A server on `clock` whose only role here is to own the clock and the limits the watchdog reads.
    private static func makeServer(clock: TestClock) throws -> HTTPServer<TestClock> {
        let limits = HTTPLimits.default.with {
            $0.headerReadTimeout = .seconds(30)
            $0.idleTimeout = .seconds(120)
            $0.keepAliveTimeout = .seconds(15)
        }
        return HTTPServer(
            transport: try TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: ClosureResponder { _, _, _ in
                ServerResponse(HTTPResponse(status: .ok), body: [])
            },
            limits: limits,
            clock: clock
        )
    }

    /// Lets any pending watchdog turn run, so "nothing fired" is a claim about a settled system.
    private static func settle() async throws {
        for _ in 0 ..< 20 {
            await Task.yield()
        }
        try await Task.sleep(for: .milliseconds(20))
    }
}
