import HTTPTestSupport
import Synchronization
import Testing

@testable import HTTPClient

/// The client's request and connect deadlines, on a test clock: a lapse is the clock advanced past the deadline's
/// sleeper, never a wait.
@Suite(.timeLimit(.minutes(1)))
struct HTTPClientDeadlineTests {
    @Test
    func `work that ends in time is returned`() async throws {
        #expect(try await withDeadline(.seconds(5), clock: TestClock()) { 7 } == 7)
    }

    @Test
    func `work still running at the deadline is cancelled, and the client reports it timed out`()
        async throws
    {
        let clock = TestClock()
        let idle = TestClock()  // never advanced: its sleep ends only when cancelled
        let cancelled = Mutex(false)
        let running = Task {
            try await withDeadline(.seconds(5), clock: clock) {
                do { try await idle.sleep(for: .seconds(3_600)) }
                catch {
                    cancelled.withLock { $0 = true }
                    throw error
                }
            }
        }
        try await clock.waitForSleepers(atLeast: 1)
        clock.advance(by: .seconds(5))
        await #expect(throws: HTTPClientError.timedOut) { try await running.value }
        let wasCancelled = cancelled.withLock(\.self)
        #expect(wasCancelled)
    }
}
