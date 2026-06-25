//
//  ResponseCache.swift
//  HTTPServer
//
//  A bounded, byte-capped LRU store of fresh responses for the RFC 9111 shared cache. One variant per
//  key: a stored response records the request values its `Vary` selected, checked on lookup, and a new
//  variant simply replaces the old. The store is Mutex-guarded (a class, since `Mutex` is non-copyable,
//  mirroring ``DateCache``) and evicts the least-recently-used entries to stay under the byte cap, so a
//  flood of distinct keys cannot grow it without bound (CWE-400).
//

internal import HTTPCore
internal import Synchronization

/// A bounded LRU cache of fresh responses, keyed by request, validated against each entry's `Vary`.
final class ResponseCache: Sendable {
    /// A stored response with its freshness bookkeeping and the request values its `Vary` selected.
    struct Entry {
        let response: ServerResponse
        let storedAt: Int
        let freshFor: Int
        let varyNames: [HTTPFieldName]
        let selecting: [String?]
        let cost: Int
    }

    private struct State {
        var entries: [String: Entry] = [:]
        var recency: [String] = []  // most-recently-used first
        var bytes = 0
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

    /// A fresh stored response for `key` whose `Vary` selection matches `request`, plus its Age (seconds).
    func lookup(
        _ key: String,
        request: HTTPRequest,
        now: Int
    ) -> (response: ServerResponse, age: Int)? {
        state.withLock { state in
            guard let entry = state.entries[key] else {
                return nil
            }
            let age = now - entry.storedAt
            guard age >= 0, age < entry.freshFor, Self.matches(entry, request) else {
                return nil
            }
            Self.touch(&state, key)
            return (entry.response, age)
        }
    }

    /// Stores `entry` under `key`, evicting least-recently-used entries to stay under the byte cap.
    func store(_ key: String, _ entry: Entry) {
        state.withLock { state in
            if let existing = state.entries[key] {
                state.bytes -= existing.cost
                state.recency.removeAll { $0 == key }
            }
            guard entry.cost <= maxBytes else {
                state.entries[key] = nil  // larger than the whole cache — not storable
                return
            }
            state.entries[key] = entry
            state.recency.insert(key, at: 0)
            state.bytes += entry.cost
            while state.bytes > maxBytes, let evicted = state.recency.last {
                state.bytes -= state.entries[evicted]?.cost ?? 0
                state.entries[evicted] = nil
                state.recency.removeLast()
            }
        }
    }

    /// Whether the stored entry still matches the request under its Vary selection (RFC 9111 §4.1).
    private static func matches(_ entry: Entry, _ request: HTTPRequest) -> Bool {
        zip(entry.varyNames, entry.selecting)
            .allSatisfy { name, value in
                request.headerFields[name] == value
            }
    }

    /// Moves `key` to the front of the recency order (most-recently-used).
    private static func touch(_ state: inout State, _ key: String) {
        state.recency.removeAll { $0 == key }
        state.recency.insert(key, at: 0)
    }
}
