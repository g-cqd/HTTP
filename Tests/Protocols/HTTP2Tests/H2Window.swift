//
//  H2Window.swift
//  HTTP2Tests
//
//  Fixtures for the consumption-gated receive-window suites (RFC 9113 §6.9, ADR 0006): a handshaked
//  connection whose stream/connection windows are set to test-sized values, a DATA-frame builder, and
//  an `Equatable` view of the WINDOW_UPDATEs on the wire.
//
//  ``H2Wire/windowUpdates(in:)`` returns tuples, which cannot be compared with `==` as a whole
//  sequence — and the whole point of these suites is asserting the exact frame *order* §6.9 implies.
//  A tiny `Equatable` struct makes each expectation a single readable comparison.
//

import HTTPCore

@testable import HTTP2

/// Fixtures for the consumption-gated receive-window suites.
enum H2Window {
    /// One WINDOW_UPDATE on the wire (RFC 9113 §6.9), comparable as a whole sequence.
    struct Update: Equatable {
        let streamID: HTTP2StreamID
        let increment: Int
    }

    /// The DATA payload size the suites feed in — the RFC 9113 §4.2 minimum SETTINGS_MAX_FRAME_SIZE,
    /// so every window under test is an exact multiple of it and no assertion needs rounding.
    static let frame = 16 * 1_024

    /// The default per-stream receive window under test.
    static let streamWindow = 64 * 1_024

    /// A handshaked connection with test-sized receive windows and (by default) a streaming route.
    ///
    /// `localSettings.initialWindowSize` is what seeds each stream's receive window, exactly as
    /// `serveHTTP2` sets it from ``HTTPLimits/streamReceiveWindow``.
    static func gated(
        streamWindow: Int = streamWindow,
        connectionWindow: Int = 1 << 20,
        localSettings: HTTP2Settings? = nil,
        streamsBody: @escaping @Sendable (HTTPRequest) -> Bool = { _ in true }
    ) throws -> HTTP2Connection {
        var settings = localSettings ?? HTTP2Settings()
        settings.initialWindowSize = streamWindow
        return try H2Wire.handshaked(
            localSettings: settings,
            limits: HTTPLimits(
                streamReceiveWindow: streamWindow,
                connectionReceiveWindow: connectionWindow
            ),
            resolveStreamsBody: streamsBody
        )
    }

    /// A DATA frame of `count` filler octets, without END_STREAM.
    ///
    /// `count` must stay within SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2) — use ``dataFrames(streamID:total:)``
    /// to offer more than one frame's worth.
    static func dataFrame(streamID: UInt32, count: Int) -> [UInt8] {
        H2Wire.data(
            streamID: streamID,
            payload: [UInt8](repeating: 0x61, count: count),
            endStream: false
        )
    }

    /// `total` filler octets split across as many maximum-size DATA frames as it takes (§4.2).
    static func dataFrames(streamID: UInt32, total: Int) -> [UInt8] {
        var wire: [UInt8] = []
        var remaining = total
        while remaining > 0 {
            let size = min(remaining, frame)
            wire += dataFrame(streamID: streamID, count: size)
            remaining -= size
        }
        return wire
    }

    /// Every WINDOW_UPDATE in `bytes`, in wire order.
    static func windowUpdates(_ bytes: [UInt8]) -> [Update] {
        H2Wire.windowUpdates(in: bytes)
            .map { Update(streamID: $0.streamID, increment: $0.increment) }
    }
}
