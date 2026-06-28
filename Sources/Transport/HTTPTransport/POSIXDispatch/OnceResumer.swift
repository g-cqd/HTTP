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
final class OnceResumer<Success: Sendable>: Sendable {
    private let continuation: Mutex<UnsafeContinuation<Success, any Error>?>

    init(_ continuation: UnsafeContinuation<Success, any Error>) {
        self.continuation = Mutex(continuation)
    }

    deinit {
        // No teardown beyond ARC.
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
