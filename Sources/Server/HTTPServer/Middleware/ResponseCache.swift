//
//  ResponseCache.swift
//  HTTPServer
//
//  A bounded, byte-capped LRU store of responses for the RFC 9111 shared cache. One variant per key: a
//  stored response records the request values its `Vary` selected, checked on lookup, and a new variant
//  simply replaces the old. The store is Mutex-guarded (a class, since `Mutex` is non-copyable,
//  mirroring ``DateCache``) and evicts the least-recently-used entries to stay under the byte cap, so a
//  flood of distinct keys cannot grow it without bound (CWE-400). A stale entry may still be served
//  within its RFC 5861 §3 `stale-while-revalidate` window while a single background revalidation runs.
//
//  Recency is an intrusive doubly-linked list of nodes (a `[key: Node]` index plus head/tail), so a
//  hit's move-to-front, an insertion, and an eviction are each O(1) regardless of how many entries the
//  cache holds — a 16 MiB default cache can hold thousands of small responses, and the previous
//  array-based recency was O(n) on every hit.
//

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

    /// One entry in the recency list: the stored value plus its neighbours.
    ///
    /// Unlinking and re-inserting at the front are O(1). Confined to the `Mutex`, never touched off the
    /// lock.
    private final class Node {
        let key: String
        var entry: Entry
        var prev: Node?
        var next: Node?

        init(key: String, entry: Entry) {
            self.key = key
            self.entry = entry
        }

        deinit {
            // No teardown beyond ARC; neighbours are mended on unlink before a node is dropped.
        }
    }

    private struct State {
        /// The entries by key; the value is the same `Node` threaded into the recency list.
        var nodes: [String: Node] = [:]
        /// The most-recently-used node (the front of the list), or nil when empty.
        var head: Node?
        /// The least-recently-used node (the eviction end), or nil when empty.
        var tail: Node?
        var bytes = 0
        /// Keys with a background revalidation already running — single-flight (RFC 5861 §3).
        var revalidating: Set<String> = []
    }

    private let state = Mutex(State())
    private let maxBytes: Int

    /// Creates a cache bounded to `maxBytes` of stored responses.
    init(maxBytes: Int) {
        self.maxBytes = max(0, maxBytes)
    }

    deinit {
        // No teardown beyond ARC; the Mutex releases with the instance.
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
            guard let node = state.nodes[key], Self.matches(node.entry, request) else {
                return nil
            }
            let entry = node.entry
            let age = now - entry.storedAt
            guard age >= 0 else {
                return nil  // stored in the future (clock skew) — treat as unusable
            }
            if age < entry.freshFor {
                Self.touch(node, &state)
                return .fresh(response: entry.response, age: age)
            }
            guard let window = entry.staleWhileRevalidate, age < entry.freshFor + window else {
                return nil  // past freshness and outside any stale-while-revalidate window
            }
            Self.touch(node, &state)
            return .staleWhileRevalidate(response: entry.response, age: age)
        }
    }

    /// Stores `entry` under `key`, evicting least-recently-used entries to stay under the byte cap.
    func store(_ key: String, _ entry: Entry) {
        state.withLock { state in
            if let existing = state.nodes[key] {
                state.bytes -= existing.entry.cost
                Self.unlink(existing, &state)
                state.nodes[key] = nil
            }
            guard entry.cost <= maxBytes else {
                // Larger than the whole cache — not storable (any prior variant was purged above).
                return
            }
            let node = Node(key: key, entry: entry)
            state.nodes[key] = node
            Self.insertAtHead(node, &state)
            state.bytes += entry.cost
            while state.bytes > maxBytes, let lru = state.tail {
                state.bytes -= lru.entry.cost
                Self.unlink(lru, &state)
                state.nodes[lru.key] = nil
            }
        }
    }

    /// Claims the single-flight revalidation slot for `key`, returning false if one is already running.
    ///
    /// Ensures at most one background `stale-while-revalidate` refresh per key (RFC 5861 §3); the caller
    /// must pair a `true` result with ``finishRevalidation(_:)`` once the refresh completes.
    func beginRevalidation(_ key: String) -> Bool {
        state.withLock { $0.revalidating.insert(key).inserted }
    }

    /// Releases the single-flight revalidation slot for `key`.
    func finishRevalidation(_ key: String) {
        state.withLock { _ = $0.revalidating.remove(key) }
    }

    /// Whether the stored entry still matches the request under its Vary selection (RFC 9111 §4.1).
    private static func matches(_ entry: Entry, _ request: HTTPRequest) -> Bool {
        zip(entry.varyNames, entry.selecting)
            .allSatisfy { name, value in
                request.headerFields[name] == value
            }
    }

    /// Moves `node` to the front of the recency order (most-recently-used) — O(1).
    private static func touch(_ node: Node, _ state: inout State) {
        guard state.head !== node else {
            return  // already most-recently-used
        }
        unlink(node, &state)
        insertAtHead(node, &state)
    }

    /// Splices `node` out of the recency list, mending its neighbours and the head/tail ends — O(1).
    private static func unlink(_ node: Node, _ state: inout State) {
        node.prev?.next = node.next
        node.next?.prev = node.prev
        if state.head === node {
            state.head = node.next
        }
        if state.tail === node {
            state.tail = node.prev
        }
        node.prev = nil
        node.next = nil
    }

    /// Inserts `node` at the front of the recency list (most-recently-used) — O(1).
    private static func insertAtHead(_ node: Node, _ state: inout State) {
        node.prev = nil
        node.next = state.head
        state.head?.prev = node
        state.head = node
        if state.tail == nil {
            state.tail = node
        }
    }
}
