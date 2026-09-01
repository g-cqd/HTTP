//
//  HTTP3StreamDeadlines.swift
//  HTTPServer
//
//  The per-connection index from QUIC stream id to its timer in the connection's ``DeadlineWheel``
//  (audit addendum P0.5). QUIC request streams had no read deadline at all before that: a peer could
//  open `maxConcurrentStreams` streams, send one octet on each, and hold every one of them — and its
//  admission slot — open indefinitely. That is the Slowloris the HTTP/1.1 reader has been defended
//  against all along (RFC 9112 §9.3), arriving over RFC 9114 §4.1.
//
//  This used to own its deadline table *and* its own scanning watchdog: `earliest()` allocated an
//  array on every wake (`values.map(\.target).min()`), `takeLapsed` allocated two more, and — the
//  correctness defect — arming a stream's 10 s header budget while the watchdog slept on another
//  stream's 60 s body budget did not wake it, so the header budget was enforced 50 s late. It is now a
//  thin index over the one wheel every deadline in the server shares, whose minimum is O(1) and whose
//  arm wakes the sleeper.
//
//  Deliberately separate from ``HTTP3StreamRegistry``: the registry answers "where does output for
//  this stream go", this answers "when must this stream have made progress by". Keeping them apart is
//  also what lets the registry stay free of the clock's `Instant` type.
//
//  Standards: RFC 9114 §4.1, §8.1; CWE-400 (uncontrolled resource consumption).
//

internal import HTTPCore
internal import Synchronization

/// The armed read deadlines of one QUIC connection's request streams, in the server clock's instants.
///
/// Armed just before a blocking `receive` and disarmed after it returns, exactly as the HTTP/1.1
/// serve loop treats its ``IdleDeadline`` — so the time a handler spends working is never charged
/// against a *read* deadline. Thread-safe and synchronous; no `await`.
final class HTTP3StreamDeadlines: Sendable {
    /// A deadline that has passed: the stream to reset, and why.
    struct Lapse: Sendable {
        let streamID: QUICStreamID
        let phase: HTTP3StreamPhase
    }

    /// One stream's timer identity plus the phase its current budget belongs to.
    private struct Tracked {
        var handle: DeadlineHandle
        var phase: HTTP3StreamPhase
    }

    private struct State {
        var tracked: [QUICStreamID: Tracked] = [:]
        /// Lapses recorded synchronously by the wheel's callback, drained by the watchdog — which is
        /// what lets retirement (an `async` engine step) happen off the callback.
        var pending: [Lapse] = []
    }

    /// The connection's timer wheel.
    ///
    /// Shared with nothing else on a QUIC connection today, but the same facility the HTTP/1.1 and
    /// HTTP/2 paths use.
    let wheel = DeadlineWheel()

    private let state = Mutex(State())

    deinit {
        // No teardown beyond ARC: the wheel dies with this index, and its watchdog task is cancelled
        // by the serve scope that owns it.
    }

    /// Arms the deadline for `id`, whose next read must complete by `instant`.
    ///
    /// The hot path — this runs around every read — is the already-tracked branch: one dictionary
    /// lookup and one in-place heap sift, no registration and no allocation.
    func arm(_ id: QUICStreamID, until key: Duration, phase: HTTP3StreamPhase) {
        let existing = state.withLock { s -> DeadlineHandle? in
            guard var tracked = s.tracked[id] else {
                return nil
            }
            tracked.phase = phase
            s.tracked[id] = tracked
            return tracked.handle
        }
        if let existing {
            wheel.arm(existing, until: key)
            return
        }
        let handle = wheel.register { [self] in
            recordLapse(of: id)
            return .keepWatching
        }
        // A concurrent first arm for the same id would otherwise leak the loser's registration. Streams
        // arm from their own single driver task, so this is a guard rather than an observed race.
        let raced = state.withLock { s -> Bool in
            guard s.tracked[id] == nil else {
                return true
            }
            s.tracked[id] = Tracked(handle: handle, phase: phase)
            return false
        }
        guard !raced else {
            wheel.release(handle)
            return
        }
        wheel.arm(handle, until: key)
    }

    /// Disarms `id` after a read returns, so the processing between reads is not timed.
    ///
    /// Keeps the registration: the stream will arm again for its next read. Retirement is what gives
    /// the slot back — see ``release(_:)``.
    func disarm(_ id: QUICStreamID) {
        guard let handle = state.withLock({ $0.tracked[id]?.handle }) else {
            return
        }
        wheel.disarm(handle)
    }

    /// Retires the timer for `id` for good.
    ///
    /// So nothing can fire against a stream this connection gave up.
    ///
    /// The ``DeadlineHandle`` generation token is what makes it final: a QUIC stream id is chosen by
    /// the peer and a wheel slot is recycled, so without it a lapse queued for a retired stream could
    /// be charged against whichever stream next occupied the slot.
    func release(_ id: QUICStreamID) {
        guard let handle = state.withLock({ s in s.tracked.removeValue(forKey: id)?.handle }) else {
            return
        }
        wheel.release(handle)
    }

    /// Takes every lapse the wheel has recorded, so each is retired exactly once.
    func takeLapsed() -> [Lapse] {
        state.withLock { s in
            let due = s.pending
            s.pending = []
            return due
        }
    }

    /// The number of streams with a tracked deadline.
    var count: Int { state.withLock(\.tracked.count) }

    /// Whether no stream has an armed deadline — every one has been disarmed or reaped.
    var isEmpty: Bool { wheel.isEmpty }

    /// Records a lapse for the watchdog to retire; runs on the watchdog's task, outside the wheel's
    /// lock, and never blocks.
    private func recordLapse(of id: QUICStreamID) {
        let handle = state.withLock { s -> DeadlineHandle? in
            guard let tracked = s.tracked.removeValue(forKey: id) else {
                return nil
            }
            s.pending.append(Lapse(streamID: id, phase: tracked.phase))
            return tracked.handle
        }
        guard let handle else {
            return
        }
        wheel.release(handle)
    }
}
