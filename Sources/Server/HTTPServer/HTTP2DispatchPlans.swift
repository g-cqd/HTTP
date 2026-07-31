//
//  HTTP2DispatchPlans.swift
//  HTTPServer
//
//  The ``DispatchPlan``s an HTTP/2 connection made at HEADERS time, held per stream until that stream
//  dispatches (2026-07-31 audit, findings 12 + 19).
//
//  HTTP/2 splits a request in two across time: the engine resolves the body policy when HEADERS decode,
//  and the driver dispatches when the body is complete — a different task, an arbitrary interval later.
//  The match made at the first moment has to survive to the second, and a stream id is the only thing
//  that identifies the request across it.
//
//  It is a `Mutex`-backed class rather than a field of `HTTP2ConnectionState` because the engine's
//  `resolveRoute` closure is `@Sendable` and cannot capture that non-`Sendable` struct. The consumer is
//  in practice the only writer *and* reader, so the lock is uncontended; it exists to satisfy the
//  isolation checker, not to arbitrate a race.
//
//  **Lifetime is the whole point.** A table keyed by a peer-chosen id grows without bound unless every
//  path that ends a stream removes its entry (CWE-401 / CWE-770). Rather than add a parallel lifetime
//  to remember, this hangs off `HTTP2ConnectionState.retire(_:)` — the single choke point every stream
//  ending already funnels through (`.requestReady`, `.streamReset`, `.tunnelEnded`, the EOF drain),
//  precisely because forgetting one of them is the class of bug that audit finding 6 was.
//

internal import HTTP2
internal import Synchronization

/// Per-stream dispatch plans for one HTTP/2 connection, filed at HEADERS and taken at dispatch.
final class HTTP2DispatchPlans: Sendable {
    private let plans = Mutex<[HTTP2StreamID: DispatchPlan]>([:])

    deinit {
        // No teardown beyond ARC; entries are plain values released with the dictionary.
    }

    /// Files the plan a stream's head resolved, keyed by its stream id.
    func file(_ plan: DispatchPlan, for streamID: HTTP2StreamID) {
        plans.withLock { $0[streamID] = plan }
    }

    /// The plan filed for `streamID`, or `nil` if its head never resolved one.
    func plan(for streamID: HTTP2StreamID) -> DispatchPlan? {
        plans.withLock { $0[streamID] }
    }

    /// Drops one stream's plan.
    ///
    /// Called from ``HTTP2ConnectionState/retire(_:)`` and nowhere else.
    func remove(_ streamID: HTTP2StreamID) {
        plans.withLock { $0[streamID] = nil }
    }

    /// The number of plans currently held (test inspection: the table must return to zero).
    var count: Int { plans.withLock(\.count) }

    /// Whether the table holds no plans at all — every stream this connection saw has been retired.
    var isEmpty: Bool { plans.withLock(\.isEmpty) }
}
