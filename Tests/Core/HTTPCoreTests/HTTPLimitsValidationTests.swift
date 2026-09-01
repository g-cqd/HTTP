//
//  HTTPLimitsValidationTests.swift
//  HTTPCoreTests
//
//  The invariants `HTTPLimits` documents are now the invariants it enforces (2026-07-31 audit,
//  CR-F15). Before this, every range below was a sentence in a doc comment and an illegal value
//  travelled straight into an engine — a `maxFrameSize` of 0 frames nothing and the read loop makes
//  no progress (RFC 9113 §4.2), a non-positive timeout expires before the read it bounds can start,
//  and a NaN `acceptResumeRatio` reached an `Int` conversion that traps (IEEE 754-2019 §7.2).
//
//  Both halves are pinned: the clamping initializer repairs, `init(validating:)` refuses, and the two
//  read the same table so they cannot disagree.
//

import Testing

@testable import HTTPCore

/// A draft carrying exactly one illegal value, for the refusal cases.
///
/// A free function so the `@Test(arguments:)` attribute can build the drafts eagerly: a closure in an
/// argument tuple would have to be `Sendable`, and the illegality is the datum worth naming anyway.
private func illegal(_ configure: (inout HTTPLimits.Draft) -> Void) -> HTTPLimits.Draft {
    var draft = HTTPLimits.Draft()
    configure(&draft)
    return draft
}

@Suite("HTTPLimits — enforced ranges (audit CR-F15)")
struct HTTPLimitsValidationTests {
    @Test(
        "an out-of-range frame size is clamped into RFC 9113 §4.2's 2^14 … 2^24-1",
        arguments: [
            (given: 0, expected: 16_384),
            (given: -1, expected: 16_384),
            (given: 16_383, expected: 16_384),
            (given: 16_384, expected: 16_384),
            (given: 1 << 20, expected: 1 << 20),
            (given: 16_777_215, expected: 16_777_215),
            (given: 16_777_216, expected: 16_777_215),
            (given: .max, expected: 16_777_215)
        ]
    )
    func frameSizeIsClamped(given: Int, expected: Int) {
        #expect(HTTPLimits(maxFrameSize: given).maxFrameSize == expected)
    }

    @Test(
        "a non-positive count is raised to the smallest value its engine can operate under",
        arguments: [Int.min, -1, 0]
    )
    func nonPositiveCountsAreRaised(_ value: Int) {
        let limits = HTTPLimits(
            maxRequestLineLength: value,
            maxFieldSize: value,
            maxFieldCount: value,
            maxDecompressionRatio: value,
            maxDecompressionLayers: value,
            maxConcurrentStreams: value,
            maxContinuationFrames: value,
            maxStreamResetsPerInterval: value,
            maxControlFramesPerInterval: value,
            maxQueuedInboundBytes: value,
            maxQueuedInboundChunks: value,
            maxQueuedBroadcasts: value,
            streamReceiveWindow: value,
            connectionReceiveWindow: value,
            requestBodyWindowSize: value,
            maxConnectionsPerClient: value,
            maxConnections: value
        )
        #expect(limits.maxRequestLineLength == 1)
        #expect(limits.maxFieldSize == 1)
        #expect(limits.maxFieldCount == 1)
        #expect(limits.maxDecompressionRatio == 1)
        #expect(limits.maxDecompressionLayers == 1)
        #expect(limits.maxConcurrentStreams == 1)
        #expect(limits.maxContinuationFrames == 1)
        #expect(limits.maxStreamResetsPerInterval == 1)
        #expect(limits.maxControlFramesPerInterval == 1)
        #expect(limits.maxQueuedInboundBytes == 1)
        #expect(limits.maxQueuedInboundChunks == 1)
        #expect(limits.maxQueuedBroadcasts == 1)
        #expect(limits.streamReceiveWindow == 1)
        #expect(limits.connectionReceiveWindow == 1)
        #expect(limits.requestBodyWindowSize == 1)
        #expect(limits.maxConnectionsPerClient == 1)
        #expect(limits.maxConnections == 1)
    }

    @Test(
        "a flow-control window above RFC 9113 §6.9.1's 2^31-1 is clamped to it",
        arguments: [2_147_483_648, Int.max]
    )
    func receiveWindowsAreClampedToTheProtocolMaximum(_ value: Int) {
        let limits = HTTPLimits(streamReceiveWindow: value, connectionReceiveWindow: value)
        #expect(limits.connectionReceiveWindow == 2_147_483_647)
        #expect(limits.streamReceiveWindow == 2_147_483_647)
    }

    @Test(
        "a non-positive duration is floored, so no deadline expires before the work it bounds starts",
        arguments: [Duration.seconds(-1), .zero]
    )
    func nonPositiveDurationsAreFloored(_ value: Duration) {
        let limits = HTTPLimits(
            bodyConsumptionTimeout: value,
            headerReadTimeout: value,
            idleTimeout: value,
            keepAliveTimeout: value,
            streamResetInterval: value
        )
        #expect(limits.bodyConsumptionTimeout > .zero)
        #expect(limits.headerReadTimeout > .zero)
        #expect(limits.idleTimeout > .zero)
        #expect(limits.keepAliveTimeout > .zero)
        #expect(limits.streamResetInterval > .zero)
    }

    @Test(
        "the accept-resume ratio is clamped where its own documentation always claimed it was",
        arguments: [
            (given: Double.nan, expected: 0.875),
            (given: .infinity, expected: 1),
            (given: -.infinity, expected: 0),
            (given: -0.5, expected: 0),
            (given: 1.5, expected: 1),
            (given: 0.25, expected: 0.25)
        ]
    )
    func resumeRatioIsClamped(given: Double, expected: Double) {
        // The clamp used to live downstream in `ConnectionAdmission` — two modules from the doc
        // comment that promised it — and it was not NaN-safe when it got there.
        #expect(HTTPLimits(acceptResumeRatio: given).acceptResumeRatio == expected)
    }

    @Test("a per-client ceiling above the global one is lowered to it")
    func perClientCeilingCannotExceedTheGlobalOne() {
        let limits = HTTPLimits(maxConnectionsPerClient: 10_000, maxConnections: 32)
        #expect(limits.maxConnectionsPerClient == 32)
        #expect(limits.maxConnections == 32)
    }

    @Test("a stream window above the connection window is lowered to it")
    func streamWindowCannotExceedTheConnectionWindow() {
        let limits = HTTPLimits(streamReceiveWindow: 8 << 20, connectionReceiveWindow: 1 << 20)
        #expect(limits.streamReceiveWindow == 1 << 20)
    }

    @Test("a decompressed cap below the raw body cap is raised to it")
    func decompressedCapCannotSitBelowTheBodyCap() {
        // A decompressed bound under the raw bound would refuse bodies that shrank on the way
        // through, having already accepted the larger compressed octets off the wire (CWE-409).
        let limits = HTTPLimits(maxBodySize: 64 << 20, maxDecompressedBodySize: 1 << 20)
        #expect(limits.maxDecompressedBodySize == 64 << 20)
    }

    @Test("every preset satisfies the validation its own values are clamped by")
    func presetsAreSelfConsistent() throws {
        for preset in [HTTPLimits.default, .hardened, .highThroughput] {
            #expect(throws: Never.self) { try HTTPLimits(validating: HTTPLimits.Draft(preset)) }
            #expect(try HTTPLimits(validating: HTTPLimits.Draft(preset)) == preset)
        }
    }

    @Test(
        "the throwing initializer refuses what the clamping one would silently repair",
        arguments: [
            (limit: HTTPLimitsError.Limit.maxFrameSize, draft: illegal { $0.maxFrameSize = 0 }),
            (limit: .maxFrameSize, draft: illegal { $0.maxFrameSize = 1 << 24 }),
            (limit: .maxConcurrentStreams, draft: illegal { $0.maxConcurrentStreams = 0 }),
            (limit: .idleTimeout, draft: illegal { $0.idleTimeout = .zero }),
            (limit: .streamResetInterval, draft: illegal { $0.streamResetInterval = .seconds(-1) }),
            (limit: .acceptResumeRatio, draft: illegal { $0.acceptResumeRatio = .nan }),
            (limit: .acceptResumeRatio, draft: illegal { $0.acceptResumeRatio = 1.5 }),
            (limit: .maxConnections, draft: illegal { $0.maxConnections = 0 }),
            (limit: .maxQueuedInboundBytes, draft: illegal { $0.maxQueuedInboundBytes = 0 })
        ]
    )
    func validatingRefusesOutOfRange(limit: HTTPLimitsError.Limit, draft: HTTPLimits.Draft) {
        guard case .outOfRange(let named, _) = capturedError(for: draft) else {
            Issue.record("expected an out-of-range refusal naming \(limit)")
            return
        }
        #expect(named == limit)
        // And the clamping initializer takes the same draft and repairs it into something that then
        // validates: the two entry points differ in what they *do* about an illegal value, never in
        // what they consider illegal. That is the property sharing one range table buys.
        let repaired = HTTPLimits.Draft(HTTPLimits(draft))
        #expect(throws: Never.self) { try HTTPLimits(validating: repaired) }
    }

    @Test("the throwing initializer names the pair when two legal values are incoherent")
    func validatingRefusesIncoherentPairs() {
        var draft = HTTPLimits.Draft()
        draft.maxConnectionsPerClient = 10_000
        draft.maxConnections = 32
        #expect(
            capturedError(for: draft)
                == .incoherent(limit: .maxConnectionsPerClient, mustNotExceed: .maxConnections)
        )
    }

    /// The error `draft` is refused with, or `nil` when validation accepted it.
    private func capturedError(for draft: HTTPLimits.Draft) -> HTTPLimitsError? {
        do {
            _ = try HTTPLimits(validating: draft)
            return nil
        }
        catch {
            return error
        }
    }
}
