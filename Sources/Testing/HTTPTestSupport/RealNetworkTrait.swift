//
//  RealNetworkTrait.swift
//  HTTPTestSupport
//
//  A concurrency bound for tests that hold real sockets, listeners and TLS handshakes.
//
//  Audit FLAKE-1, second half. Raising the liveness budgets (see ``TestLivenessBudget``) removed most
//  of the transport suite's intermittent failures but not all of them, and the residual is the more
//  interesting one, because no deadline can fix it.
//
//  The measurement: `UnixSocketTransportTests` completes its three tests in **0.003 s** when run alone,
//  eight runs out of eight. Under `swift test --parallel --filter HTTPTransportTests` the same suite
//  intermittently records *zero* events in **thirty seconds**. That is four orders of magnitude, which
//  is not a slow machine — it is starvation. `HTTPTransportTests` runs 68 tests across 15 suites at
//  once, most of them binding a listener, opening loopback connections, and completing a real TLS
//  handshake through Network.framework's own dispatch queues.
//
//  And parallelism buys this target nothing. Serially the whole thing takes 50–68 s and passed 3 runs
//  out of 3; in parallel it takes 26–63 s and fails intermittently. The work is dominated by waiting on
//  real network I/O, not by CPU, so running it all at once mostly produces contention.
//
//  Hence a permit rather than `.serialized`: serializing a suite does not help, because the contention
//  is *between* suites, and serializing the target would need every suite nested inside one type. A
//  bounded number of concurrent network-bearing tests keeps the parallelism that pays (across the other
//  twelve test targets, which are sans-I/O and finish in milliseconds) and removes the part that does
//  not.
//

public import Testing

/// Bounds how many network-bearing tests run at once, across every suite that opts in.
///
/// Apply to a suite or test that binds a listener, opens a loopback connection, or performs a TLS
/// handshake:
///
/// ```swift
/// @Suite("Transport — UNIX-domain-socket backbone", .realNetwork)
/// ```
///
/// Sans-I/O tests must **not** take a permit. They finish in microseconds, and queueing them behind a
/// TLS handshake would trade a real bug for a slow suite.
public struct RealNetworkTrait: TestTrait, SuiteTrait, TestScoping {
    /// Applies to each test rather than once per suite, so the permit is held for a test's lifetime.
    public var isRecursive: Bool { true }

    /// Runs `function` holding one of the ``RealNetworkPermits`` permits.
    public func provideScope(
        for _: Test,
        testCase: Test.Case?,
        performing function: @Sendable () async throws -> Void
    ) async throws {
        // The suite's own scope is not a permit holder — only its test cases are, which is where the
        // sockets are. Taking one here would hold it for the suite's whole lifetime and deadlock any
        // suite with more test cases than the pool has permits.
        guard testCase != nil else {
            try await function()
            return
        }
        try await RealNetworkPermits.shared.withPermit(performing: function)
    }
}

extension Trait where Self == RealNetworkTrait {
    /// Bounds how many network-bearing tests run at once (audit FLAKE-1).
    public static var realNetwork: Self { Self() }
}
