//
//  HTTPLimitsTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the failsafe default limits and their customizability.
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
        #expect(limits.maxBodySize == 1 << 30)
        #expect(limits.maxConcurrentStreams == 1_048_576)
        #expect(limits.maxFrameSize == 16 * 1_024)
        #expect(limits.headerTableSize == 4 * 1_024)
        #expect(limits.maxContinuationFrames == 100)
        #expect(limits.headerReadTimeout == .seconds(10))
        #expect(limits.idleTimeout == .seconds(60))
        #expect(limits.keepAliveTimeout == .seconds(15))
        #expect(limits.maxConnectionsPerClient == 1_048_576)
        #expect(limits.maxConnections == 1_048_576)
    }

    @Test("individual limits can be overridden while others keep their defaults")
    func customizable() {
        var limits = HTTPLimits.default
        limits.maxConcurrentStreams = 250
        #expect(limits.maxConcurrentStreams == 250)

        let custom = HTTPLimits(maxBodySize: 4_096)
        #expect(custom.maxBodySize == 4_096)
        #expect(custom.maxConcurrentStreams == 1_048_576)
    }
}
