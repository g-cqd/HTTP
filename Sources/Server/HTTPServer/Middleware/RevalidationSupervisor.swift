//
//  RevalidationSupervisor.swift
//  HTTPServer
//
//  The admission gate for background `stale-while-revalidate` refreshes (RFC 5861 §3). Serving a stale
//  response is cheap; refreshing it is a whole second trip through the responder, and the request that
//  triggered it has already been answered — so nothing downstream is waiting, nothing applies
//  backpressure, and nothing counts them. N distinct stale keys therefore used to produce N unstructured
//  `Task`s and an unbounded set of in-flight keys, on an input a remote client chooses freely (CWE-400).
//
//  Two bounds fix that, and both are hard: at most `maxConcurrent` refreshes exist at any instant, and
//  each is raced against `deadline`. Refreshes over the bound are DROPPED, not queued — a queue only
//  moves the unbounded growth from the task pool into the queue, and a refresh is worth doing only while
//  it is still timely. Dropping one costs freshness, never correctness: the stale response was already
//  served, and the next request simply revalidates synchronously.
//

internal import Synchronization

/// Bounds background `stale-while-revalidate` refreshes: at most `maxConcurrent`, each under `deadline`.
///
/// **The deadline is cooperative, not preemptive** — the same contract ``TimeoutMiddleware`` documents,
/// and for the same reason. On expiry the supervisor stops waiting for the refresh and cancels it, but a
/// `withTaskGroup` scope cannot return until every child has actually exited, so the permit comes back
/// only once the refresh reaches its next suspension point. A responder that blocks a thread (a
/// synchronous `sleep`, a blocking syscall, an unbounded CPU loop) holds its permit for its own full
/// runtime. Releasing the permit early while leaving the refresh running would trade a bounded stall for
/// exactly the unbounded leak of runaway tasks this type exists to prevent, so it is not offered; hard
/// isolation against uncooperative handler code needs a process boundary, not a Swift task.
final class RevalidationSupervisor: Sendable {
    /// The refreshes currently admitted, by key.
    ///
    /// One set is both the permit counter and the single-flight index, which is the point: the audit
    /// found a per-key `Set` guarding duplicates with no cap and a task count with no cap, in two
    /// different objects, and either could be claimed without the other. Here `count` *is* the number of
    /// permits taken, so the two bounds cannot drift apart and a key can never be admitted without
    /// consuming a permit.
    private let inFlight: Mutex<Set<String>>
    private let maxConcurrent: Int
    private let deadline: Duration
    private let spawn: @Sendable (@escaping @Sendable () async -> Void) -> Void

    /// Creates a supervisor admitting `maxConcurrent` refreshes at a time, each bounded by `deadline`.
    ///
    /// `spawn` is the seam that detaches a refresh from the served response; it defaults to an
    /// unstructured `Task` and a test injects one it can deterministically settle.
    init(
        maxConcurrent: Int,
        deadline: Duration,
        spawn: @escaping @Sendable (@escaping @Sendable () async -> Void) -> Void
    ) {
        self.inFlight = Mutex([])
        self.maxConcurrent = max(0, maxConcurrent)
        self.deadline = deadline
        self.spawn = spawn
    }

    deinit {
        // No teardown beyond ARC. Already-spawned refreshes are detached by construction and end on
        // their own deadline; the supervisor holds no reference to them to cancel.
    }

    /// Runs `work` if a permit is free and no refresh for `key` is already running; false otherwise.
    ///
    /// The permit is released on every exit path — normal return, thrown error inside `work`,
    /// cancellation, and deadline expiry — because the release is a `defer` around the whole raced
    /// scope rather than a statement at the end of the happy path.
    @discardableResult
    func submit(key: String, _ work: @escaping @Sendable () async -> Void) -> Bool {
        guard claim(key) else {
            return false
        }
        let deadline = self.deadline
        spawn { [self] in
            defer { release(key) }
            await Self.race(work, against: deadline)
        }
        return true
    }

    /// Takes a permit for `key`, or returns false when saturated or already refreshing that key.
    ///
    /// One critical section for the whole compound decision: a `count` check and an `insert` split
    /// across two acquisitions is how a bound that reads correctly still fails to hold under load.
    private func claim(_ key: String) -> Bool {
        inFlight.withLock { keys in
            guard keys.count < maxConcurrent else {
                return false
            }
            return keys.insert(key).inserted
        }
    }

    /// Returns the permit held for `key`.
    private func release(_ key: String) {
        inFlight.withLock { _ = $0.remove(key) }
    }

    /// Runs `work`, cancelling it once `deadline` elapses.
    ///
    /// Cooperative — see the type documentation. `ContinuousClock` because a refresh budget is a
    /// duration of real elapsed time and must not move when the wall clock is stepped.
    private static func race(
        _ work: @escaping @Sendable () async -> Void,
        against deadline: Duration
    ) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await work() }
            group.addTask { try? await ContinuousClock().sleep(for: deadline) }
            _ = await group.next()  // whichever finishes first: the refresh, or its deadline
            group.cancelAll()
        }
    }
}
