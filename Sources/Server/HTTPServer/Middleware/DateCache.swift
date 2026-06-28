//
//  DateCache.swift
//  HTTPServer
//
//  A per-thread cache for the IMF-fixdate `Date` header (RFC 9110 §5.6.7). The formatted string only
//  changes once a second, so rebuilding it on every response — 200k string builds a second at the target
//  rate — is pure waste. The earlier design shared one string behind a `Mutex`, which every response on
//  every event loop then contended on. Because the server pins each connection's work to a single
//  event-loop thread (audit R4), this instead keeps the cache **per thread** (a `pthread` key): each
//  loop thread reads and writes only its own slot, so the per-response path takes **no lock at all**.
//  A thread rebuilds its string only when the whole-second tick advances; the key's destructor releases
//  a thread's slot when it exits.
//

internal import HTTPCore

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// A lock-free, per-thread cache of the IMF-fixdate `Date` string (RFC 9110 §5.6.7).
final class DateCache: Sendable {
    /// One thread's cached `(second, formatted string)`.
    ///
    /// Touched only by its owning thread, so its mutable state needs no synchronization — the `pthread`
    /// key gives each thread a distinct box.
    private final class ThreadCache {
        var second = Int.min
        var value = ""

        deinit {
            // Freed by the `pthread` key destructor when the owning thread exits; nothing more to do.
        }
    }

    /// The process-wide `pthread` key naming each thread's ``ThreadCache`` slot, created once.
    ///
    /// Its destructor balances the `passRetained` in ``formatted(for:)`` when a thread exits. One key
    /// serves every `DateCache` instance: the date is global, so sharing a thread's box across instances
    /// is harmless (and there is normally a single instance anyway).
    private static let key: pthread_key_t = {
        var key = pthread_key_t()
        pthread_key_create(&key) { raw in
            // `raw` is an exiting thread's retained ThreadCache pointer — release the +1 it holds.
            Unmanaged<ThreadCache>.fromOpaque(raw).release()
        }
        return key
    }()

    deinit {
        // No teardown: each per-thread box is owned by its `pthread` key slot and freed on thread exit.
    }

    /// The IMF-fixdate string for `second` (seconds since the Unix epoch), formatted at most once per
    /// second **on the calling thread**: a same-second call returns the thread's cached string with no
    /// allocation and no lock; a new second rebuilds only this thread's copy.
    func formatted(for second: Int) -> String {
        let cache: ThreadCache
        if let existing = pthread_getspecific(Self.key) {
            cache = Unmanaged<ThreadCache>.fromOpaque(existing).takeUnretainedValue()
        }
        else {
            // First touch on this thread: create its box and hand the slot a +1 to own until thread exit.
            let fresh = ThreadCache()
            pthread_setspecific(Self.key, Unmanaged.passRetained(fresh).toOpaque())
            cache = fresh
        }
        if cache.second != second {
            cache.second = second
            cache.value = HTTPDate.imfFixdate(second)
        }
        return cache.value
    }
}
