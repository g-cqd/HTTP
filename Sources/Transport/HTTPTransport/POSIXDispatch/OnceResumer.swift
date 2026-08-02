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
/// A resumer can outlive a single I/O op: a ``DirectionOwner`` caches one per direction and
/// ``claim(_:)``s it per operation, so the hot path allocates no fresh resumer per receive/send
/// (audit: tail-latency variance). Reuse is sound because the owner admits one operation at a time,
/// and — should that ever stop being true — because ``claim(_:)`` refuses to displace a pending
/// continuation rather than dropping it.
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

    /// Installs `continuation` as the pending one for this operation, refusing to displace one that is
    /// already there; returns whether the slot was taken.
    ///
    /// A refusal means the ownership contract is broken, not that the caller should retry: a
    /// ``DirectionOwner`` hands this resumer out only to the operation that owns the direction, so at
    /// most one caller can legitimately be here at a time. When it happens anyway the REJECTED
    /// continuation is resumed at once with ``DirectionOwnershipViolation`` — the intruder is the one
    /// with no claim, and the incumbent keeps the slot it is about to be resumed through by readiness
    /// or by close.
    ///
    /// This replaces an unconditional `self.continuation.withLock { $0 = continuation }` whose own doc
    /// comment stated the invariant it did not enforce ("the caller guarantees the previous
    /// continuation was already taken"). Nothing serialized them, so the displaced continuation was
    /// resumed by nothing and its task stayed suspended for the life of the process (CWE-833). Failing
    /// the intruder is what makes the contract testable: the exclusion above prevents the collision,
    /// and this makes its removal loud instead of silent.
    ///
    /// The rejection resumes OUTSIDE the lock, so a continuation's resumption never runs under it.
    ///
    /// SE-0458 (ADR 0009): the two `unsafe` steps are storing the continuation and resuming a rejected
    /// one. Both are sound for the same reason the type is: the slot is read, written and emptied only
    /// under the `Mutex`, which is what provides the single-resume guarantee, and a continuation
    /// yielded to a resumer is removed from the slot in the same locked step — so no second resumal of
    /// the same continuation can be produced, and a rejected one was never in the slot at all.
    @discardableResult
    func claim(_ continuation: UnsafeContinuation<Success, any Error>) -> Bool {
        let admitted = self.continuation.withLock { pending in
            guard unsafe pending == nil else {
                return false
            }
            unsafe pending = continuation
            return true
        }
        if !admitted {
            unsafe continuation.resume(throwing: DirectionOwnershipViolation())
        }
        return admitted
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
