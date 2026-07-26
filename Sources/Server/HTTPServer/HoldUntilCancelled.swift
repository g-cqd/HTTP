//
//  HoldUntilCancelled.swift
//  HTTPServer
//
//  FIX #8 — a cancellation-driven suspension with zero periodic wakeups, replacing a poll loop that
//  slept-and-rechecked once a second purely to retain references for the task's lifetime. Used by the
//  HTTP/3 control/QPACK unidirectional stream keep-alive and any future server-side holder.
//

internal import Synchronization

/// The parked state of ``holdUntilCancelled()``: a single continuation, plus whether cancellation has
/// already fired, guarded by a `Mutex` so the park and the cancel resolve exactly once between them.
private struct CancellationPark {
    var cancelled = false
    var continuation: CheckedContinuation<Void, Never>?
}

/// Suspends the current task until it is cancelled — with **zero** periodic wakeups (FIX #8).
///
/// A single `withCheckedContinuation` resumed only by the cancellation handler, replacing a poll loop
/// that slept-and-rechecked once a second purely to retain some references for the task's lifetime. The
/// pre-park cancellation check (resume immediately when the state already shows `cancelled`) closes the
/// already-cancelled and cancel-before-park races, so the continuation is resumed exactly once and never
/// leaks. Resumes happen outside the lock, matching the loop/gate primitives elsewhere in the stack.
///
/// `internal` (not `private`) only so the concurrency property has a direct deterministic test; it is
/// never part of the public API.
func holdUntilCancelled() async {
    let state = Mutex(CancellationPark())
    await withTaskCancellationHandler {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let resumeNow = state.withLock { park -> Bool in
                if park.cancelled {
                    // onCancel already fired (or the task was cancelled before we parked)
                    return true
                }
                park.continuation = continuation
                return false
            }
            if resumeNow {
                continuation.resume()
            }
        }
    } onCancel: {
        let continuation = state.withLock { park -> CheckedContinuation<Void, Never>? in
            park.cancelled = true
            defer { park.continuation = nil }
            return park.continuation
        }
        continuation?.resume()
    }
}
