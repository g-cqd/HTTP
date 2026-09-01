//
//  HTTPLimitsTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the failsafe default limits, the ranges every value is now held to, and the
//  two ways in — clamping and throwing (2026-07-31 audit, CR-F15).
//
//  The default pin is deliberate and is the point of the suite: these numbers are a security posture,
//  so moving one has to be a decision somebody made rather than a diff that slipped through.
//

import Testing

@testable import HTTPCore

@Suite("HTTPLimits — failsafe defaults")
struct HTTPLimitsTests {
    @Test("default limits match the documented safe values")
    func documentedDefaults() {
        let limits = HTTPLimits.default
        #expect(limits.maxRequestLineLength == 8 * 1_024)
        #expect(limits.maxFieldSize == 16 * 1_024)
        #expect(limits.maxHeaderListSize == 64 * 1_024)
        #expect(limits.maxFieldCount == 100)
        #expect(limits.maxBodySize == 16 << 20)
        #expect(limits.maxWebSocketMessageSize == 4 << 20)
        #expect(limits.effectiveWebSocketMessageSize == 4 << 20)
        #expect(limits.maxDecompressedBodySize == 64 << 20)
        #expect(limits.maxConcurrentStreams == 128)
        #expect(limits.maxFrameSize == 16 * 1_024)
        #expect(limits.headerTableSize == 4 * 1_024)
        #expect(limits.maxContinuationFrames == 100)
        #expect(limits.maxStreamResetsPerInterval == 100)
        #expect(limits.maxControlFramesPerInterval == 1_000)
        #expect(limits.headerReadTimeout == .seconds(10))
        #expect(limits.idleTimeout == .seconds(60))
        #expect(limits.keepAliveTimeout == .seconds(15))
        #expect(limits.maxConnectionsPerClient == 64)
        #expect(limits.maxConnections == 16_384)
    }

    @Test("the WebSocket reassembly cap does not follow the body cap by default")
    func webSocketCapIsExplicit() {
        // It used to default to `nil`, which meant "follow maxBodySize" — so the reassembly buffer
        // silently inherited a 1 GiB HTTP body cap that nothing about RFC 6455 §5.4 framing justified.
        #expect(HTTPLimits.default.maxWebSocketMessageSize != nil)
        #expect(HTTPLimits.default.effectiveWebSocketMessageSize < HTTPLimits.default.maxBodySize)
        // The coupling is still expressible for a caller who wants exactly it.
        let coupled = HTTPLimits(maxBodySize: 4_096, maxWebSocketMessageSize: nil)
        #expect(coupled.effectiveWebSocketMessageSize == 4_096)
    }

    @Test("individual limits can be overridden while others keep their defaults")
    func customizable() {
        let limits = HTTPLimits.default.with { $0.maxConcurrentStreams = 250 }
        #expect(limits.maxConcurrentStreams == 250)
        #expect(limits.maxFieldCount == HTTPLimits.default.maxFieldCount)

        let custom = HTTPLimits(maxBodySize: 4_096)
        #expect(custom.maxBodySize == 4_096)
        #expect(custom.maxConcurrentStreams == 128)
    }

    @Test("a round trip through the draft preserves every field")
    func draftRoundTripsEveryField() {
        // The guard on the mirror: `Draft` restates all thirty properties, and a field forgotten in
        // either direction would silently fall back to its default instead of failing to compile.
        // Every value below differs from the default, so a dropped field shows up as an inequality.
        let limits = HTTPLimits(
            maxRequestLineLength: 4_097,
            maxFieldSize: 4_098,
            maxHeaderListSize: 4_099,
            maxFieldCount: 41,
            maxBodySize: 4_100,
            maxWebSocketMessageSize: 4_101,
            maxDecompressedBodySize: 4_102,
            maxDecompressionRatio: 42,
            maxDecompressionLayers: 43,
            maxConcurrentStreams: 44,
            maxFrameSize: 20_000,
            headerTableSize: 4_103,
            maxContinuationFrames: 45,
            maxStreamResetsPerInterval: 46,
            maxControlFramesPerInterval: 47,
            maxQueuedInboundBytes: 4_104,
            maxQueuedInboundChunks: 48,
            maxQueuedBroadcasts: 49,
            streamReceiveWindow: 4_105,
            connectionReceiveWindow: 4_106,
            bodyConsumptionTimeout: .seconds(51),
            requestBodyWindowSize: 4_107,
            keepAliveBufferCapacity: 4_108,
            headerReadTimeout: .seconds(52),
            idleTimeout: .seconds(53),
            keepAliveTimeout: .seconds(54),
            streamResetInterval: .seconds(55),
            maxConnectionsPerClient: 56,
            maxConnections: 57,
            acceptResumeRatio: 0.5
        )
        let untouched = limits.with { _ in
            // No override: the round trip through the draft is itself the assertion.
        }
        #expect(untouched == limits)
        #expect(HTTPLimits(HTTPLimits.Draft(limits)) == limits)
    }

    @Test("highThroughput restores the old ceilings without weakening the header guards")
    func highThroughputPreset() {
        let limits = HTTPLimits.highThroughput
        // maxConcurrentStreams stays bounded even here — it is a memory bound, never a throughput one.
        #expect(limits.maxConcurrentStreams == 128)
        #expect(limits.maxConnectionsPerClient == 1_048_576)
        #expect(limits.maxConnections == 1_048_576)
        // The conservative header guards are unchanged — only the ceilings are raised.
        #expect(limits.maxFieldCount == 100)
        // The pre-CR-F15 size ceilings, reachable in one word.
        #expect(limits.maxBodySize == 1 << 30)
        #expect(limits.effectiveWebSocketMessageSize == 1 << 30)
    }

    @Test("hardened preset tightens every ceiling below the default")
    func hardenedPreset() {
        let base = HTTPLimits.default
        let hardened = HTTPLimits.hardened
        #expect(hardened.maxConcurrentStreams < base.maxConcurrentStreams)
        #expect(hardened.maxConnections < base.maxConnections)
        #expect(hardened.maxConnectionsPerClient < base.maxConnectionsPerClient)
        #expect(hardened.maxBodySize < base.maxBodySize)
        #expect(hardened.effectiveWebSocketMessageSize < base.effectiveWebSocketMessageSize)
        #expect(hardened.maxDecompressedBodySize < base.maxDecompressedBodySize)
        #expect(hardened.idleTimeout < base.idleTimeout)
    }
}
