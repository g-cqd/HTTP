//
//  HTTP3StreamDeadlines.swift
//  HTTPServer
//
//  The per-connection table of HTTP/3 request-stream read deadlines (audit addendum P0.5). QUIC
//  request streams had none: a peer could open `maxConcurrentStreams` streams, send one octet on each,
//  and hold every one of them — and its admission slot — open indefinitely. That is the Slowloris the
//  HTTP/1.1 reader has been defended against all along (RFC 9112 §9.3), arriving over RFC 9114 §4.1.
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
/// against a *read* deadline. Thread-safe and synchronous; one `Mutex`, no `await`.
final class HTTP3StreamDeadlines<Instant: Comparable & Sendable>: Sendable {
    /// One stream's armed deadline.
    private struct Armed {
        var target: Instant
        var phase: HTTP3StreamPhase
    }

    /// A deadline that has passed: the stream to reset, and why.
    struct Lapse: Sendable {
        let streamID: QUICStreamID
        let phase: HTTP3StreamPhase
    }

    private let armed = Mutex<[QUICStreamID: Armed]>([:])

    deinit {
        // No teardown beyond ARC.
    }

    /// Arms the deadline for `id`, whose next read must complete by `instant`.
    func arm(_ id: QUICStreamID, until instant: Instant, phase: HTTP3StreamPhase) {
        armed.withLock { $0[id] = Armed(target: instant, phase: phase) }
    }

    /// Disarms `id` after a read returns, so the processing between reads is not timed.
    func disarm(_ id: QUICStreamID) {
        armed.withLock { $0[id] = nil }
    }

    /// The earliest armed deadline, so a watchdog can sleep exactly until it rather than poll.
    func earliest() -> Instant? {
        armed.withLock { current in current.values.map(\.target).min() }
    }

    /// Takes every deadline that has passed at `now`, removing them so each lapses exactly once.
    func takeLapsed(at now: Instant) -> [Lapse] {
        armed.withLock { current in
            let due = current.filter { $0.value.target <= now }
            for id in due.keys {
                current[id] = nil
            }
            return due.map { Lapse(streamID: $0.key, phase: $0.value.phase) }
        }
    }

    /// The number of streams with an armed deadline.
    var count: Int {
        armed.withLock(\.count)
    }
}
