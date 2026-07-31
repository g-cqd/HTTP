//
//  HTTP2StreamCanceller.swift
//  HTTPServer
//
//  A per-stream cancellation handle for the HTTP/2 merged-mailbox consumer (2026-07-31 audit, F6).
//
//  Ending a stream's *inbound* is not enough to end its handler. Abandoning the body channel unblocks a
//  handler parked reading the body, but one parked anywhere else — a database call, a sleep, a lock —
//  keeps running until the whole connection dies. On a peer RST_STREAM (RFC 9113 §6.4) that is work the
//  server is doing for a request the client has explicitly withdrawn, which is exactly the amplification
//  Rapid Reset exploits (CVE-2023-44487).
//
//  Structured concurrency is preserved: the task-group child still owns the lifetime and
//  `group.cancelAll()` still reaps everything on teardown. The inner unstructured `Task` exists only so
//  there is a *handle* to cancel early, and the child awaits it through a cancellation handler so the
//  two cancellation paths compose.
//
//  Scope. Applied to streaming requests and tunnels only — the two paths that can park indefinitely and
//  are opt-in, off the hot path. A buffered request would pay an extra `Task` plus a `Mutex` per
//  request against a 200k-rps target, and the existing Rapid Reset defenses (`chargeStreamReset`, and
//  the MadeYouReset charge in HTTP2Connection) already bound that amplification.
//

internal import Synchronization

/// A one-shot cancellation handle for one HTTP/2 stream's handler or pump task.
final class HTTP2StreamCanceller: Sendable {
    /// Whether a task has been adopted yet, and whether cancellation has already been asked for.
    ///
    /// The `cancelled` state is what closes the race: the dispatching child adopts its task a moment
    /// *after* the consumer has registered this canceller, so a reset arriving in between must not be
    /// forgotten. Adoption then cancels immediately instead.
    private enum State {
        case idle
        case adopted(@Sendable () -> Void)
        case cancelled
    }

    private let state = Mutex<State>(.idle)

    /// Adopts `task`, cancelling it at once if ``cancel()`` has already run.
    func adopt<Success: Sendable>(_ task: Task<Success, Never>) {
        let alreadyCancelled = state.withLock { state -> Bool in
            guard case .cancelled = state else {
                state = .adopted { task.cancel() }
                return false
            }
            return true
        }
        if alreadyCancelled {
            task.cancel()
        }
    }

    /// Cancels the adopted task, or arms ``adopt(_:)`` to cancel on arrival.
    ///
    /// Idempotent: a stream can be reset by the peer and swept as stalled, and the teardown path is
    /// shared, so this is called more than once for the same stream in practice.
    func cancel() {
        let pending = state.withLock { state -> (@Sendable () -> Void)? in
            defer { state = .cancelled }
            guard case .adopted(let cancel) = state else {
                return nil
            }
            return cancel
        }
        pending?()
    }

    deinit {
        // No teardown beyond ARC.
    }
}
