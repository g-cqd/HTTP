//
//  DateCache.swift
//  HTTPServer
//
//  A per-second cache for the IMF-fixdate `Date` header (RFC 9110 §5.6.7). The formatted string only
//  changes once a second, so rebuilding it on every response — 200k string builds a second at the
//  target rate — is pure waste. This rebuilds only when the whole-second tick advances and otherwise
//  hands back the shared string (a retain, zero allocation). `Mutex`-guarded because one middleware
//  value is shared across every connection's task; a reference type so the cache is shared, not copied.
//

internal import HTTPCore
internal import Synchronization

/// A thread-safe per-second cache of the IMF-fixdate `Date` string (RFC 9110 §5.6.7).
final class DateCache: Sendable {
    private let state = Mutex<(second: Int, value: String)>((second: Int.min, value: ""))

    deinit {
        // No teardown beyond ARC; the Mutex releases with the instance.
    }

    /// The IMF-fixdate string for `second` (seconds since the Unix epoch), formatted once per second:
    /// a same-second call returns the cached string with no allocation; a new second rebuilds it.
    func formatted(for second: Int) -> String {
        state.withLock { cache in
            if cache.second != second {
                cache = (second, HTTPDate.imfFixdate(second))
            }
            return cache.value
        }
    }
}
