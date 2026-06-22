//
//  HTTP2AbuseBudgetTests.swift
//  HTTP2Tests
//
//  Audit H2-F1/F2 — the time-windowed reset/control-frame budget. A server-emitted RST_STREAM counts
//  toward the budget (so MadeYouReset, CVE-2025-8671, cannot bypass the Rapid-Reset defense by
//  provoking resets the client never sends), and the budget decays over `streamResetInterval` (so a
//  cap is a rate, not a monotonic per-connection total). Driven via the injected `TestClock`.
//
//  An extension of `HTTP2ConnectionTests` so it reuses that suite's frame fixtures.
//

import HPACK
import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

extension HTTP2ConnectionTests {

    @Test("server-emitted RST_STREAM counts toward the budget (MadeYouReset, CVE-2025-8671)")
    func madeYouReset() {
        var connection = HTTP2Connection(limits: HTTPLimits(maxStreamResetsPerInterval: 5))
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        var streamID: UInt32 = 1
        // Ten self-dependent HEADERS: each is a §5.3.1 violation that makes the *server* emit
        // RST_STREAM. The client never sends a single RST_STREAM, yet the budget must still trip —
        // otherwise the Rapid-Reset defense is bypassed (MadeYouReset).
        for _ in 0..<10 {
            wire += selfDependentHeadersFrame(streamID: streamID)
            streamID += 2
        }
        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(wire)
        } catch {
            thrown = error.code
        }
        #expect(thrown == .enhanceYourCalm)
    }

    @Test("the reset budget decays over the rolling window (Rapid-Reset is a rate, not a total)")
    func resetBudgetDecays() throws {
        let clock = TestClock()
        let limits = HTTPLimits(maxStreamResetsPerInterval: 5, streamResetInterval: .seconds(1))
        var connection = HTTP2Connection(limits: limits, now: clock.nowProvider)
        _ = connection.outboundBytes()
        var first = HTTP2ConnectionPreface.client
        first += settingsFrame()
        var streamID: UInt32 = 1
        for _ in 0..<5 {  // exactly at the cap within the first window — no trip
            first += openStream(streamID: streamID)
            first += rstStreamFrame(streamID: streamID)
            streamID += 2
        }
        _ = try connection.receive(first)  // does not throw

        clock.advance(by: .seconds(2))  // past the rolling window → the budget resets

        var second = [UInt8]()
        for _ in 0..<5 {  // five more resets — allowed only because the window decayed
            second += openStream(streamID: streamID)
            second += rstStreamFrame(streamID: streamID)
            streamID += 2
        }
        #expect(throws: Never.self) { try connection.receive(second) }
    }
}
