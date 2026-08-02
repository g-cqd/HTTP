//
//  DirectionOwner.swift
//  HTTPTransport
//
//  The raw-connection operation-ownership contract, in ONE place — because this was the fourth site in
//  the 2026-07-31 audit where a single continuation slot was overwritten by a second operation, and the
//  first three fixes were each correct, each local, and each left the shape intact one layer up.
//
//  The contract: a raw connection is an ordered octet stream with exactly one sequence space per
//  direction (RFC 9293 §3.1), so exactly ONE operation owns a direction at a time, for the WHOLE of
//  that operation — readiness plus the scratch copy-out on the way in, readiness plus every
//  partial-write / writev / sendfile retry on the way out. Request parallelism belongs above this
//  seam: HTTP/2 stream multiplexing (RFC 9113 §5), HTTP/3 over QUIC streams (RFC 9114 §2, RFC 9000 §2).
//
//  The two directions stay INDEPENDENT — one owner per direction, never one per connection. HTTP/2
//  deliberately runs a continuous reader and a sole writer in separate tasks, so a read and a write in
//  flight together is a supported state, not a contradiction; a connection-wide lock would trade a lost
//  wakeup for a bottleneck on every connection the server holds.
//
//  Enforcement is structural rather than documented, which is the whole point of the type. The
//  ``OnceResumer`` is private here and handed out only inside ``withOwnership(_:)``, so an operation
//  cannot install a continuation without first holding the direction; and the resumer itself refuses to
//  displace a pending continuation (``DirectionOwnershipViolation``), so a caller that reaches it
//  without ownership fails at once rather than parking on a continuation nothing will resume (CWE-833).
//
//  ``AsyncExclusion`` rather than a `Mutex`, because the critical section spans an `await` on a peer
//  that may never act and a thread-blocking lock cannot be held across a suspension. Rather than an
//  `actor`, because actor methods are reentrant: a second caller enters the moment the first `await`s,
//  which is precisely the interleaving being excluded. It is NOT reentrant, so a gated entry point must
//  never call another gated entry point on the same direction — keep the ungated core in its own method.
//

internal import HTTPConcurrency

/// The sole owner of one direction of a raw connection's octet stream.
///
/// `Success` is what the direction's parked continuation resumes with — a byte count for a receive,
/// `Void` for a send. Operations are admitted FIFO, so a stream of later arrivals cannot starve one
/// already waiting, and a caller cancelled while merely QUEUED throws `CancellationError` without
/// disturbing the operation that owns the direction.
final class DirectionOwner<Success: Sendable>: Sendable {
    /// Suspends — never blocks — the operations queued behind the owner.
    private let exclusion = AsyncExclusion()

    /// The owning operation's parked continuation, reachable only from inside ``withOwnership(_:)``.
    ///
    /// One instance per direction for the connection's whole life, ``OnceResumer/claim(_:)``ed per
    /// operation, so the hot path allocates no fresh resumer (audit: tail-latency variance). Reuse is
    /// sound *because* of the exclusion — no longer because a comment asserts operations are serial.
    private let resumer = OnceResumer<Success>()

    /// An unowned direction with nothing queued.
    init() {
        // Both members are self-initializing; there is no other setup.
    }

    deinit {
        // No teardown beyond ARC. A queued operation's cancellation handler retains the exclusion, so
        // it cannot be released while anyone is waiting on it.
    }

    /// Whether an operation currently owns this direction.
    ///
    /// The oracle a caller asserts its discipline against, and the one a test reads: a claim in a
    /// comment cannot fail, `#expect(owner.isOwned)` can.
    var isOwned: Bool { exclusion.isHeld }

    /// Operations suspended waiting for the current owner to finish.
    var queuedOperations: Int { exclusion.waiterCount }

    /// Runs `operation` as this direction's sole owner, suspending until the operation ahead of it has
    /// finished — all of it, not just its readiness wait.
    ///
    /// `operation` receives the direction's resumer, which is the only way to reach it: installing a
    /// continuation is therefore possible only while holding the direction. Ownership is released
    /// however the body ends — return, `throw`, or cancellation — so a torn-down connection cannot
    /// leave a direction owned by a task that is already gone.
    func withOwnership<T>(_ operation: (OnceResumer<Success>) async throws -> T) async throws -> T {
        try await exclusion.withExclusiveAccess { try await operation(resumer) }
    }

    /// Suspends until at least `count` operations are queued behind the owner.
    ///
    /// The deterministic replacement for a `Task.yield()` spin when a caller needs to observe the
    /// contended moment rather than hope to catch it.
    func waitForQueued(atLeast count: Int) async throws {
        try await exclusion.waitForWaiters(atLeast: count)
    }
}
