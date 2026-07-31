//
//  ResponseCache.swift
//  HTTPServer
//
//  A bounded, byte-capped LRU store of responses for the RFC 9111 shared cache. One variant per key: a
//  stored response records the request values its `Vary` selected, checked on lookup, and a new variant
//  simply replaces the old. The store is Mutex-guarded (a class, since `Mutex` is non-copyable,
//  mirroring ``DateCache``) and evicts the least-recently-used entries to stay under the byte cap, so a
//  flood of distinct keys cannot grow it without bound (CWE-400). A stale entry may still be served
//  within its RFC 5861 §3 `stale-while-revalidate` window while a background revalidation runs; which
//  refreshes are admitted, and how many, is ``RevalidationSupervisor``'s decision, not this store's.
//
//  Recency is ``BoundedLRU``: an index-linked list over a contiguous slab of slots, `Int32` offsets
//  rather than object references. Move-to-front, insertion and eviction stay O(1), and — unlike the
//  hand-rolled `class`-node list this replaced — there is nothing for ARC to cycle on, so dropping the
//  cache releases every stored response instead of leaking all of them (CWE-401, audit finding 14).
//

internal import HTTPConcurrency
internal import HTTPCore
internal import Synchronization

/// A bounded LRU cache of responses, keyed by request, validated against each entry's `Vary`.
final class ResponseCache: Sendable {
    /// A stored response with its freshness bookkeeping and the request values its `Vary` selected.
    struct Entry {
        let response: ServerResponse
        let storedAt: Int
        let freshFor: Int
        /// The RFC 5861 §3 `stale-while-revalidate` window (seconds past freshness), if any.
        let staleWhileRevalidate: Int?
        let varyNames: [HTTPFieldName]
        let selecting: [String?]
        let cost: Int
    }

    /// The outcome of a lookup: a usable stored response and whether it is fresh or servable-while-stale.
    enum Lookup {
        /// A fresh stored response (RFC 9111 §4.2) and its Age in seconds.
        case fresh(response: ServerResponse, age: Int)
        /// A stale response still inside its `stale-while-revalidate` window (RFC 5861 §3), and its Age.
        case staleWhileRevalidate(response: ServerResponse, age: Int)
    }

    private struct State {
        var entries: BoundedLRU<String, Entry>
    }

    private let state: Mutex<State>

    /// The floor on any entry's accounted cost — the fixed per-entry overhead ``CacheMiddleware`` adds.
    ///
    /// ``BoundedLRU`` bounds both an entry count and a total cost, but this cache advertises only a byte
    /// cap. Deriving the count bound from the byte cap and this floor keeps the count bound *implied* by
    /// the byte bound rather than a second, surprising limit: no entry can cost less than the floor, so
    /// the byte cap is what evicts. The count bound still has to exist — a cost of zero would otherwise
    /// let entries accumulate under an untouched byte total (CWE-400).
    static let minimumEntryCost = 512

    /// Creates a cache bounded to `maxBytes` of stored responses.
    init(maxBytes: Int) {
        let maxBytes = max(0, maxBytes)
        self.state = Mutex(
            State(
                entries: BoundedLRU(
                    capacity: max(1, maxBytes / Self.minimumEntryCost),
                    maxCost: maxBytes
                )
            )
        )
    }

    deinit {
        // No teardown beyond ARC; the Mutex — and every slot in the slab it guards — releases with the
        // instance. That is the property the `class`-node recency list could not provide.
    }

    /// The total accounted cost of the stored entries, in bytes — never above the configured cap.
    var storedBytes: Int {
        state.withLock(\.entries.cost)
    }

    /// A usable stored response for `key` whose `Vary` selection matches `request`, or nil.
    ///
    /// Returns ``Lookup/fresh(response:age:)`` while within the freshness lifetime, then
    /// ``Lookup/staleWhileRevalidate(response:age:)`` while past it but inside the `stale-while-
    /// revalidate` window (RFC 5861 §3), and nil once neither applies (a miss, a Vary mismatch, or a
    /// stale entry past its window — the caller revalidates synchronously).
    func lookup(
        _ key: String,
        request: HTTPRequest,
        now: Int
    ) -> Lookup? {
        state.withLock { state in
            // `value(forKey:)` first, `touchedValue(forKey:)` only once the entry proves usable: an
            // unusable entry (Vary mismatch, expired, clock-skewed) must not be promoted, or a miss
            // would keep dead weight resident ahead of live entries.
            guard let entry = state.entries.value(forKey: key), Self.matches(entry, request) else {
                return nil
            }
            let age = now - entry.storedAt
            guard age >= 0 else {
                return nil  // stored in the future (clock skew) — treat as unusable
            }
            if age < entry.freshFor {
                _ = state.entries.touchedValue(forKey: key)
                return .fresh(response: entry.response, age: age)
            }
            guard let limit = Self.staleLimit(entry), age < limit else {
                return nil  // past freshness and outside any stale-while-revalidate window
            }
            _ = state.entries.touchedValue(forKey: key)
            return .staleWhileRevalidate(response: entry.response, age: age)
        }
    }

    /// Stores `entry` under `key`, evicting least-recently-used entries to stay under the byte cap.
    ///
    /// An entry whose own cost exceeds the whole cap is not stored, and any previously stored variant
    /// under `key` is removed with it, so a caller never reads a stale variant it believes it replaced.
    func store(_ key: String, _ entry: Entry) {
        state.withLock { state in
            _ = state.entries.insert(entry, forKey: key, cost: entry.cost)
        }
    }

    /// The age at which `entry` stops being servable stale, or nil when it has no window.
    ///
    /// `addingReportingOverflow` rather than `+`: after RFC 9111 §1.2.2 clamping (see ``CacheControl``
    /// and ``CacheMiddleware/staleWhileRevalidate(_:)``) both operands are at most 2147483648, so this
    /// cannot overflow — the reporting form is the assertion that the clamp holds. Treating an overflow
    /// as "no window" fails closed: the entry is simply not served stale.
    private static func staleLimit(_ entry: Entry) -> Int? {
        guard let window = entry.staleWhileRevalidate else {
            return nil
        }
        let (limit, overflowed) = entry.freshFor.addingReportingOverflow(window)
        return overflowed ? nil : limit
    }

    /// Whether the stored entry still matches the request under its Vary selection (RFC 9111 §4.1).
    private static func matches(_ entry: Entry, _ request: HTTPRequest) -> Bool {
        zip(entry.varyNames, entry.selecting)
            .allSatisfy { name, value in
                request.headerFields[name] == value
            }
    }
}
