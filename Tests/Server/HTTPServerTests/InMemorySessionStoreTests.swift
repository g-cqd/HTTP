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

    @Test("registering past the cap prunes expired sessions, bounding memory")
    func boundedByPrune() async {
        let clock = TestClock()
        let store = InMemorySessionStore(ttl: .seconds(10), maxSessions: 2) { clock.nanos }
        await store.register("a")
        await store.register("b")  // at the cap
        clock.nanos = seconds(20)  // a and b are now past the TTL
        await store.register("c")  // at the cap → prunes a, b before inserting c
        #expect(await store.validate("a") == false)
        #expect(await store.validate("c"))  // freshly registered at 20s
    }
}
