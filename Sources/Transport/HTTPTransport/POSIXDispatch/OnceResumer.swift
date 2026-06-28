//
//  OnceResumer.swift
//  HTTPTransport
//
//  Resumes an UnsafeContinuation at most once. Readiness / DispatchIO read/write handlers may be
//  invoked more than once per operation (re-arm on EAGAIN, the close-race wakeup), so this `Mutex`
//  serializes the take and **provides the single-resume guarantee itself** — which is exactly why the
//  underlying continuation can be `Unsafe` rather than `Checked`: the runtime's double-resume
//  detection (a per-resume task-status-record lock the profiler flagged on the I/O hot path) would be
//  redundant work here (audit: tail-latency variance). The `Mutex` also makes the type genuinely
//  `Sendable` (no `@unchecked`).
//

internal import Synchronization

/// Resumes an `UnsafeContinuation` at most once, regardless of how many times its callback fires.
///
/// A resumer can outlive a single I/O op: when a connection serializes its reads (and its writes)
/// it caches one resumer and ``reset(_:)``s it per op, so the hot path allocates no fresh resumer
/// per receive/send (audit: tail-latency variance). Reuse is sound only because the prior
/// continuation is always taken before the next op installs its own.
final class OnceResumer<Success: Sendable>: Sendable {
    private let continuation: Mutex<UnsafeContinuation<Success, any Error>?>

    init(_ continuation: UnsafeContinuation<Success, any Error>) {
        self.continuation = Mutex(continuation)
    }

    /// Creates an empty resumer with no pending continuation, ready to be ``reset(_:)`` for its first
    /// op — the cached, reused form.
    init() {
        self.continuation = Mutex(nil)
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Installs `continuation` as the new pending one for the next op.
    ///
    /// The caller guarantees the previous continuation was already taken (ops are serialized on the
    /// connection), so this only ever overwrites an empty slot — the single-resume guarantee holds
    /// across reuse exactly as it does for a freshly allocated resumer.
    func reset(_ continuation: UnsafeContinuation<Success, any Error>) {
        self.continuation.withLock { $0 = continuation }
    }

    func resume(returning value: Success) {
        take()?.resume(returning: value)
    }

    func resume(throwing error: any Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> UnsafeContinuation<Success, any Error>? {
        continuation.withLock { pending in
            defer { pending = nil }
            return pending
        }
    }
}
