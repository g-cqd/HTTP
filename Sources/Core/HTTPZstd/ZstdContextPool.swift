//
//  ZstdContextPool.swift
//  HTTPZstd
//
//  Reuses libzstd contexts across calls. A context at level 3 holds about 3.5 MiB of tables, and creating one clears
//  them; a reused one starts a new frame without clearing (libzstd invalidates by index). The pool keeps a few per
//  level (and per decoder window limit), so a server coding many small responses allocates once, while an idle
//  pool never holds more than `capacity` contexts per key.
//

internal import Synchronization

/// A bounded pool of contexts keyed by an integer (a level, or a window limit).
final class ZstdContextPool<Context: AnyObject & Sendable>: Sendable {
    private let capacity: Int
    private let idle = Mutex<[Int: [Context]]>([:])

    init(capacity: Int) {
        self.capacity = capacity
    }

    deinit {
        // The idle contexts free their libzstd state as the dictionary releases them.
    }

    /// An idle context for `key`, or a new one from `make`.
    func take(_ key: Int, make: (Int) throws(ZstdError) -> Context) throws(ZstdError) -> Context {
        if let context = idle.withLock({ contexts in contexts[key]?.popLast() }) {
            return context
        }
        return try make(key)
    }

    /// Returns `context` (already reset) for reuse, or drops it when `key` already has `capacity` idle ones.
    func give(_ key: Int, _ context: Context) {
        idle.withLock { contexts in
            if contexts[key, default: []].count < capacity {
                contexts[key, default: []].append(context)
            }
        }
    }
}
