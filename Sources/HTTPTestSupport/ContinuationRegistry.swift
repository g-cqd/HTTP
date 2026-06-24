//
//  ContinuationRegistry.swift
//  HTTPTestSupport
//
//  Shared park / wake / cancel infrastructure for the deterministic coordination primitives —
//  `TestClock` (key = wake deadline), `AsyncEventProbe` (key = event threshold), and `AsyncGate`
//  (key = 0, FIFO). A set of suspended continuations, each parked under a `Key` and woken in `Key`
//  order once a boundary advances past it. Iterative throughout (no recursion).
//

internal import HeapModule

/// A set of suspended continuations parked under a `Key`, woken in `Key` order.
///
/// A `Heap` keeps the parked keys ordered, so a wake pops only the entries that are due (O(log n) per
/// pop) instead of scanning and sorting every parked continuation. A side table maps id →
/// (key, continuation) as the source of truth for liveness, giving O(1) cancellation; a cancelled
/// entry's heap slot is left in place and skipped when later reached (lazy deletion), so cancellation
/// never scans the heap.
///
/// Not `Sendable` (it holds raw continuations) — it lives inside a `Mutex`-guarded state. Resume
/// continuations **outside** the lock.
struct ContinuationRegistry<Key: Comparable, Value> {
    /// A parked key plus the id that ties it back to the liveness table.
    ///
    /// Ordered by key, then id, so equal keys wake in a stable, deterministic order.
    private struct Entry: Comparable {
        let key: Key
        let id: UInt64
        static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.key == rhs.key ? lhs.id < rhs.id : lhs.key < rhs.key
        }
    }

    private var ordered = Heap<Entry>()
    private var live: [UInt64: (key: Key, continuation: UnsafeContinuation<Value, any Error>)] = [:]
    private var nextID: UInt64 = 0

    /// The number of *live* parked continuations (cancelled / woken ones excluded).
    var count: Int { live.count }

    /// The furthest parked key still live, or `nil` if none — the "drain to the end" boundary.
    var maxKey: Key? { live.values.map(\.key).max() }

    /// Vends a fresh identifier so the caller can build its cancellation handler before it decides
    /// whether to actually park.
    mutating func makeID() -> UInt64 {
        defer { nextID &+= 1 }
        return nextID
    }

    /// Parks `continuation` under `key`, keyed by a previously-vended `id`.
    mutating func park(id: UInt64, key: Key, _ continuation: UnsafeContinuation<Value, any Error>) {
        live[id] = (key, continuation)
        ordered.insert(Entry(key: key, id: id))
    }

    /// Removes and returns every live continuation whose key is `<= bound`, in ascending key order,
    /// each paired with `value`.
    ///
    /// Stale (cancelled) slots are dropped silently.
    mutating func wake(
        upTo bound: Key, with value: Value
    ) -> [(
        UnsafeContinuation<Value, any Error>, Value
    )] {
        var woken: [(UnsafeContinuation<Value, any Error>, Value)] = []
        while let next = ordered.min, next.key <= bound {
            _ = ordered.popMin()
            if let parked = live.removeValue(forKey: next.id) {
                woken.append((parked.continuation, value))
            }
        }
        return woken
    }

    /// Removes and returns the single longest-waiting live continuation (lowest key, then lowest id),
    /// skipping stale slots — a one-permit release for gate / semaphore use.
    mutating func wakeOne() -> UnsafeContinuation<Value, any Error>? {
        while let next = ordered.min {
            _ = ordered.popMin()
            if let parked = live.removeValue(forKey: next.id) {
                return parked.continuation
            }
        }
        return nil
    }

    /// Removes and returns the continuation parked under `id` (for cancellation), if still live.
    ///
    /// Its heap slot is left for `wake` to skip.
    mutating func remove(id: UInt64) -> UnsafeContinuation<Value, any Error>? {
        live.removeValue(forKey: id)?.continuation
    }
}
