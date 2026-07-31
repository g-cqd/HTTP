//
//  H2Gate.swift
//  HTTPServerTests
//
//  A handshaked ``HTTP2Connection`` plus the frames to open and fill a gated stream, for the tests that
//  exercise ``HTTP2ConnectionState`` decisions directly rather than through a whole serve loop.
//
//  The stall sweeper's rule is a pure function of byte progress, so it is worth testing without a clock
//  or a connection at all; this is the minimum scaffolding that needs.
//

import HTTP2
import HTTPCore

/// Sans-I/O scaffolding for the ``HTTP2ConnectionState`` unit tests.
enum H2Gate {
    /// A connection past the preface + SETTINGS handshake, with its outbound preface drained.
    static func handshaked(limits: HTTPLimits, streaming: Bool) throws -> HTTP2Connection {
        var settings = HTTP2Settings()
        settings.initialWindowSize = limits.streamReceiveWindow
        let streamsBody: @Sendable (HTTPRequest) -> Bool = { _ in streaming }
        var connection = HTTP2Connection(
            localSettings: settings,
            limits: limits,
            resolveStreamsBody: streamsBody
        )
        _ = connection.outboundBytes()
        _ = try connection.receive(H2ServerWire.preface + H2ServerWire.settings())
        _ = connection.outboundBytes()
        return connection
    }

    /// HEADERS opening `streamID` for a streaming route, plus `count` octets of DATA on it.
    static func openAndFill(streamID: HTTP2StreamID, count: Int) -> [UInt8] {
        H2ServerWire.headers(streamID: streamID.rawValue, path: "/upload")
            + H2ServerWire.dataFrames(streamID: streamID.rawValue, total: count)
    }
}
