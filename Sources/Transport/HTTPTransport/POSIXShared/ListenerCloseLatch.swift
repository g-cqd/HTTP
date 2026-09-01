//
//  ListenerCloseLatch.swift
//  HTTPTransport
//
//  A one-shot latch every `shutdown()` caller awaits, so "the listening descriptor is closed" is a fact
//  the whole set of callers observes rather than a fact only the caller who happened to perform the
//  close observes.
//
//  Idempotence and synchrony pull in opposite directions here, and the naive combination is wrong in a
//  way that only shows up under load. Making `shutdown()` idempotent means exactly one caller may take
//  the listening descriptor out of the transport's state and close it; making it synchronous means no
//  caller may return before that close lands. Without a shared latch the losers of that race return
//  *immediately* — they find `listenFD == -1` and have nothing to wait on — so a rebind issued right
//  after the call they awaited still fails `bind(2)` with `EADDRINUSE`.
//
//  That is not hypothetical: `ServerTransport.start(admission:)` wires `continuation.onTermination` to
//  an unawaited `Task { await shutdown() }`, so *every* consumer that drops the connection stream races
//  the explicit `shutdown()`. When the termination task wins, the explicit caller is a loser. The Linux
//  job found it (bind-contract `rebind after stop`, errno 98) against a first fix that had every other
//  part of the ordering right.
//
//  Standards: `close(2)`/`bind(2)` per POSIX.1-2017 (IEEE Std 1003.1-2017) — the local address stays
//  bound to a listening socket until it is closed, which is why the wait has to cover every caller.
//  CWE-404 (improper resource shutdown or release).
//

internal import Synchronization

/// A latch that is signalled once and awaited by any number of callers.
///
/// Signalling is idempotent and never blocks; waiting after the signal returns without suspending. The
/// continuations are resumed OUTSIDE the lock, so a waiter's resumption never runs under it.
final class ListenerCloseLatch: Sendable {
    private let state = Mutex<State>(State())

    private struct State {
        var isSignalled = false
        /// Callers parked until the close lands.
        ///
        /// Empty in the common case — one performer and, at most, the stream-termination task
        /// behind it.
        var waiters: [CheckedContinuation<Void, Never>] = []
    }

    init() {
        // Nothing beyond the mutex's defaults.
    }

    deinit {
        // No teardown beyond ARC. A latch that is dropped unsignalled has no waiters by construction:
        // a waiter holds the transport, which holds the latch.
    }

    /// Marks the listening descriptor closed and releases every parked caller.
    func signal() {
        let parked = state.withLock { state -> [CheckedContinuation<Void, Never>] in
            state.isSignalled = true
            defer { state.waiters = [] }
            return state.waiters
        }
        for waiter in parked {
            waiter.resume()
        }
    }

    /// Suspends until ``signal()`` has been called, returning at once if it already has.
    func wait() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let alreadyClosed = state.withLock { state -> Bool in
                guard !state.isSignalled else {
                    return true
                }
                state.waiters.append(continuation)
                return false
            }
            if alreadyClosed {
                continuation.resume()
            }
        }
    }
}
