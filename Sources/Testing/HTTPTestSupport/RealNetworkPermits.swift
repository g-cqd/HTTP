//
//  RealNetworkPermits.swift
//  HTTPTestSupport
//
//  The permit pool behind ``RealNetworkTrait`` — the reason for the bound is recorded there.
//
//  A counting semaphore rather than a lock: a test holds its permit across `await`s spanning a whole
//  TLS handshake, so blocking an OS thread for it would starve the cooperative pool that the waiting
//  tests need in order to make progress — the very failure this exists to stop, reproduced one level
//  down. ``AsyncGate`` already banks permits and suspends `Task`s, so the pool is that gate opened
//  `permits` times.
//

internal import Foundation

/// A process-wide bound on concurrently running network-bearing tests.
public struct RealNetworkPermits: Sendable {
    /// The shared pool every ``RealNetworkTrait``-marked test draws from.
    public static let shared = Self(permits: defaultPermits)

    /// The default bound, overridable with `HTTP_TEST_NETWORK_PERMITS`.
    ///
    /// Four, not "one per core": these tests are almost entirely *waiting* — on a loopback connect, on
    /// a handshake, on the peer's echo — so the bound that matters is on how many listeners, sockets
    /// and Network.framework dispatch queues exist at once, which core count does not predict. Four
    /// was the smallest value that made the suite reliable here without lengthening it; it is a
    /// measured setting, not a derived one, and the environment override exists because a different
    /// host may measure differently.
    public static let defaultPermits: Int = {
        guard
            let raw = ProcessInfo.processInfo.environment["HTTP_TEST_NETWORK_PERMITS"],
            let parsed = Int(raw)
        else {
            return 4
        }
        return max(1, parsed)
    }()

    private let gate: AsyncGate

    /// Creates a pool of `permits` concurrent holders (clamped to at least one).
    public init(permits: Int) {
        gate = AsyncGate(initiallyOpen: true)
        for _ in 1 ..< max(1, permits) {
            gate.open()
        }
    }

    /// The number of tests currently queued for a permit — the pool's own diagnostic.
    public var waitingCount: Int { gate.waiterCount }

    /// Runs `body` holding one permit, returning it however `body` ends.
    ///
    /// A cancelled acquisition throws before the `defer` is installed, so a permit that was never taken
    /// is never returned — the accounting bug that would otherwise let the pool grow without bound over
    /// a run and quietly stop bounding anything.
    public func withPermit(performing body: @Sendable () async throws -> Void) async throws {
        try await gate.waitUntilOpen()
        defer { gate.open() }
        try await body()
    }
}
