//
//  InMemorySessionStoreTests.swift
//  HTTPServerTests
//
//  Phase 2.6 — the in-memory ``SessionStore``: register / validate / revoke, the sliding TTL (each
//  validate refreshes a session's lifetime, idle ones expire), and the bounded-map prune. Time is an
//  injected monotonic clock, so expiry is pinned with no real waiting.
//

import HTTPConcurrency
import HTTPServer
import Testing

@Suite("Phase 2.6 — in-memory session store")
struct InMemorySessionStoreTests {
    /// A controllable monotonic clock (sequential test use only).
    private final class TestClock: @unchecked Sendable {
        var nanos: MonotonicNanoseconds = 0

        deinit {
            // No teardown beyond ARC.
        }
    }

    private func seconds(_ value: Int64) -> MonotonicNanoseconds { value * 1_000_000_000 }

    @Test("registers, validates, and revokes a session")
    func registerValidateRevoke() async {
        let store = InMemorySessionStore()
        #expect(await store.validate("a") == false)  // never registered
        await store.register("a")
        #expect(await store.validate("a"))
        await store.revoke("a")
        #expect(await store.validate("a") == false)  // revoked
    }

    @Test("a session expires after the TTL of inactivity, and each validate slides it")
    func slidingExpiry() async {
        let clock = TestClock()
        let store = InMemorySessionStore(ttl: .seconds(10)) { clock.nanos }
        await store.register("a")  // last-seen = 0s
        clock.nanos = seconds(9)
        #expect(await store.validate("a"))  // alive; slides last-seen to 9s
        clock.nanos = seconds(18)
        #expect(await store.validate("a"))  // 9s since the slide — alive; slides to 18s
        clock.nanos = seconds(29)
        #expect(await store.validate("a") == false)  // 11s since 18s — expired
    }

    @Test("registering past the cap reclaims expired sessions, bounding memory")
    func boundedByReclaim() async {
        let clock = TestClock()
        let store = InMemorySessionStore(ttl: .seconds(10), maxSessions: 2) { clock.nanos }
        await store.register("a")
        await store.register("b")  // at the cap
        clock.nanos = seconds(20)  // a and b are now past the TTL
        await store.register("c")  // at the cap → reclaims a, b before inserting c
        #expect(await store.validate("a") == false)
        #expect(await store.validate("c"))  // freshly registered at 20s
    }

    @Test("registering more LIVE sessions than the cap still holds the bound")
    func boundedAgainstLiveSessions() async {
        let clock = TestClock()
        let maximum = 8
        let store = InMemorySessionStore(ttl: .seconds(3_600), maxSessions: maximum) {
            clock.nanos
        }
        // The clock never advances, so nothing is expired and nothing is reclaimable. The previous
        // implementation pruned only expired ids, found none, and inserted anyway — so the map grew
        // to 200 with a cap of 8 (CWE-400). Eviction (not refusal) is right here: refusing to
        // register would make the just-minted cookie fail its next validate, forever.
        for index in 0 ..< 200 {
            await store.register("session-\(index)")
        }
        var live = 0
        for index in 0 ..< 200 where await store.validate("session-\(index)") {
            live += 1
        }
        #expect(live <= maximum)
        #expect(live >= 1)
        #expect(await store.validate("session-199"))  // the most recent is always still there
    }

    @Test("validate slides the TTL and promotes, so the eviction victim is the most idle")
    func validatePromotesTheSession() async {
        let clock = TestClock()
        let store = InMemorySessionStore(ttl: .seconds(3_600), maxSessions: 2, shards: 1) {
            clock.nanos
        }
        await store.register("a")
        await store.register("b")
        #expect(await store.validate("a"))  // a is now the most recently used; b is the victim
        await store.register("c")
        #expect(await store.validate("a"))
        #expect(await store.validate("b") == false)
        #expect(await store.validate("c"))
    }
}
