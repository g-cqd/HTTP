//
//  HoldUntilCancelledTests.swift
//  HTTPServerTests
//
//  FIX #8 — an HTTP/3 connection's control/QPACK unidirectional streams are held open by a single
//  cancellation-driven suspension (`holdUntilCancelled`) instead of a 1 Hz keep-alive poll: zero
//  periodic wakeups per connection, the exact same lifetime, and a prompt resume on cancellation under
//  either race order (parked-then-cancelled, and cancel-before-park).
//

import HTTPTestSupport
import Testing

@testable import HTTPServer

@Suite("FIX #8 — holdUntilCancelled (HTTP/3 stream keep-alive, no periodic wakeup)")
struct HoldUntilCancelledTests {
    @Test(
        "stays parked with no periodic resume, then resumes promptly on cancellation",
        .timeLimit(.minutes(1)))
    func resumesWhenCancelledAfterParking() async {
        let finished = AsyncEventProbe<Void>()
        let task = Task {
            await holdUntilCancelled()
            finished.record(())
        }
        // With no timer/poll, the suspension cannot resume on its own: after ample scheduling
        // opportunity it must still be parked (the property the old 1 Hz loop violated every second).
        for _ in 0 ..< 100 {
            await Task.yield()
        }
        #expect(finished.count == 0)  // no spurious / periodic wakeup

        task.cancel()
        // Must resume on cancellation, not hang (the .timeLimit fails a hang).
        _ = try? await finished.wait(forAtLeast: 1, timeout: .seconds(3))
        await task.value
        #expect(finished.count == 1)
    }

    @Test(
        "resumes under a cancel-before-park race, repeated — never hangs, never double-resumes",
        .timeLimit(.minutes(1)))
    func resumesUnderCancelRace() async {
        // A group child cancelled the instant it is added: sometimes cancellation lands before the
        // child parks (the already-cancelled path), sometimes after (the parked path). Either way the
        // child must return — a never-resumed continuation would hang the group past the time limit; a
        // double resume would trap. Repeated to cover both interleavings.
        for _ in 0 ..< 200 {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await holdUntilCancelled() }
                group.cancelAll()
                await group.waitForAll()
            }
        }
    }
}
