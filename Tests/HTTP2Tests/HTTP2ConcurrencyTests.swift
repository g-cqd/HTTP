//
//  HTTP2ConcurrencyTests.swift
//  HTTP2Tests
//
//  RFC 9113 §5.1.2 — the server advertises and enforces SETTINGS_MAX_CONCURRENT_STREAMS, a
//  per-connection bound on open streams. Unbounded concurrent streams is a stream-state exhaustion DoS
//  (each open stream allocates a record), and an unenforced / impractically huge cap makes a
//  conformance client that tries to exceed it (h2spec 5.1.2) hang. The cap is exact: at the cap is
//  allowed, one past it is refused with REFUSED_STREAM while the connection stays alive (§5.4.2).
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

@Suite("RFC 9113 §5.1.2 — stream concurrency cap", .tags(.mutation))
struct HTTP2ConcurrencyTests {
    @Test("advertises a finite SETTINGS_MAX_CONCURRENT_STREAMS in the server preface")
    func advertisesCap() throws {
        var connection = HTTP2Connection(limits: HTTPLimits(maxConcurrentStreams: 128))
        let preface = connection.outboundBytes()
        let settings = try #require(
            H2Wire.frames(in: preface).first { $0.header.type == .settings })
        var parsed = HTTP2Settings()
        settings.payload.withUnsafeBytes { _ = try? parsed.apply($0.bytes) }
        #expect(parsed.maxConcurrentStreams == 128)
    }

    @Test("at the cap is allowed; one stream past it is refused with REFUSED_STREAM")
    func refusesPastCap() throws {
        var connection = try H2Wire.handshaked(limits: HTTPLimits(maxConcurrentStreams: 2))
        H2Wire.expectAccepted(H2Wire.openStream(streamID: 1), on: &connection)  // 1 open
        H2Wire.expectAccepted(H2Wire.openStream(streamID: 3), on: &connection)  // 2 open (at cap)
        // The 3rd concurrent stream exceeds the cap: a stream error, the connection survives (§5.4.2).
        H2Wire.expectStreamError(
            .refusedStream,
            on: 5,
            feeding: H2Wire.openStream(streamID: 5),
            connection: &connection
        )
    }
}
