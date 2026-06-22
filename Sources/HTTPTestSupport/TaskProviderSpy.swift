//
//  TaskProviderSpy.swift
//  HTTPTestSupport
//
//  A `TaskProvider` for tests that spawns *real* tasks (so the work actually runs) while tracking
//  them, then settles them deterministically. Code that takes a `TaskProvider` (defaulting to
//  `LiveTaskProvider` in production) is handed this in a test; instead of racing on a `Task.sleep`,
//  the test triggers the work and `await spy.waitForAllTasks()`.
//

public import HTTPConcurrency
// `#_sourceLocation` (the default arg of `AsyncEventProbe.init`) expands at this call site, so the
// Testing macro must be importable here even though no `Testing` type is named directly.
internal import Testing

/// A tracking ``TaskProvider`` that settles its spawned `.work` tasks transitively.
///
/// Two ``AsyncEventProbe``s record each `.work` spawn and each completion; ``waitForAllTasks()`` loops
/// — waiting for all-spawned-so-far to complete, then re-checking whether the wait itself spawned
/// more — until the spawn count stabilizes with everything complete. `.observation` tasks (long-lived
/// loops that never finish on their own) are excluded, so awaiting them can never hang the suite. The
/// settle deadline is clock-injectable, so it is real-time-free under a ``TestClock``.
public final class TaskProviderSpy: TaskProvider, Sendable {
    private let spawnProbe = AsyncEventProbe<Void>()
    private let completeProbe = AsyncEventProbe<Void>()

    /// Creates a spy with no tasks tracked yet.
    public init() {}

    /// `.work` tasks spawned so far (the ones ``waitForAllTasks()`` settles).
    public var spawnedCount: Int { spawnProbe.count }

    /// `.work` tasks that have finished.
    public var completedCount: Int { completeProbe.count }

    /// `.work` tasks still in flight.
    public var liveCount: Int { spawnProbe.count - completeProbe.count }

    /// Spawns a tracked non-throwing task; a `.work` role is recorded for settling, others forwarded.
    @discardableResult
    public func task<Success: Sendable>(
        role: TaskRole,
        priority: TaskPriority?,
        @_inheritActorContext operation: sending @escaping @isolated(any) () async -> Success
    ) -> Task<Success, Never> {
        guard role == .work else {
            return Task(priority: priority, operation: operation)
        }
        spawnProbe.record(())
        let completeProbe = self.completeProbe
        return Task(priority: priority) {
            defer { completeProbe.record(()) }
            return await operation()
        }
    }

    /// Spawns a tracked throwing task; a `.work` role is recorded for settling, others forwarded.
    @discardableResult
    public func task<Success: Sendable>(
        role: TaskRole,
        priority: TaskPriority?,
        @_inheritActorContext operation: sending @escaping @isolated(any) () async throws -> Success
    ) -> Task<Success, any Error> {
        guard role == .work else {
            return Task(priority: priority, operation: operation)
        }
        spawnProbe.record(())
        let completeProbe = self.completeProbe
        return Task(priority: priority) {
            defer { completeProbe.record(()) }
            return try await operation()
        }
    }

    /// Settles every `.work` task transitively, racing a `clock`-driven deadline.
    ///
    /// Call *after* triggering the work (the spawn is recorded synchronously by `task`). Throws
    /// ``AsyncEventProbeTimeoutError`` if a task hangs past the deadline. `duration` is a single
    /// **global** budget: the deadline is fixed once, and each re-check waits only for the time
    /// *remaining* against it.
    public func waitForAllTasks<C: Clock>(within duration: C.Duration, clock: C) async throws {
        let deadline = clock.now.advanced(by: duration)
        while true {
            let target = spawnProbe.count
            if target == 0 { return }
            let remaining = clock.now.duration(to: deadline)
            _ = try await completeProbe.wait(forAtLeast: target, within: remaining, clock: clock)
            if spawnProbe.count == target { return }
        }
    }

    /// Convenience over `ContinuousClock` with a generous real-time deadline.
    public func waitForAllTasks(timeout: Duration = .seconds(2)) async throws {
        try await waitForAllTasks(within: timeout, clock: ContinuousClock())
    }
}
