//
//  HTTP2ConnectionTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for the RFC 9113 sans-I/O connection engine: the preface + SETTINGS handshake,
//  decoding a GET and a POST-with-body into request events, fragmented delivery, and the bad-preface
//  rejection.
//

import HPACK
import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP2

@Suite("RFC 9113 — connection engine")
struct HTTP2ConnectionTests {

    // MARK: Handshake + request decoding

    @Test("performs the handshake and decodes a GET request")
    func decodesGetRequest() throws {
        var connection = HTTP2Connection()
        #expect(!connection.outboundBytes().isEmpty)  // server SETTINGS preface queued at init

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/index.html")

        let events = try connection.receive(wire)
        #expect(events.count == 1)
        let event = try #require(events.first)
        guard case .request(let streamID, let request, let body) = event else {
            Issue.record("expected a request event")
            return
        }
        #expect(streamID == HTTP2StreamID(1))
        #expect(request.method == .get)
        #expect(request.scheme == "https")
        #expect(request.path == "/index.html")
        #expect(request.authority == "example.com")
        #expect(body.isEmpty)
        #expect(!connection.outboundBytes().isEmpty)  // SETTINGS ACK queued
    }

    @Test("decodes a POST request with a DATA body")
    func decodesPostWithBody() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += headersFrame(
            streamID: 1,
            fields: [
                HPACKField(name: ":method", value: "POST"),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: "/submit"),
                HPACKField(name: ":authority", value: "example.com"),
            ], endStream: false)
        wire += dataFrame(streamID: 1, payload: Array("hello world".utf8), endStream: true)

        let events = try connection.receive(wire)
        let event = try #require(events.first)
        guard case .request(_, let request, let body) = event else {
            Issue.record("expected a request event")
            return
        }
        #expect(request.method == .post)
        #expect(String(decoding: body, as: UTF8.self) == "hello world")
    }

    @Test("assembles a request delivered across two reads")
    func fragmentedDelivery() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/")

        let split = wire.count / 2
        #expect(try connection.receive(wire[..<split]).isEmpty)  // partial — nothing yet
        let events = try connection.receive(wire[split...])
        #expect(events.count == 1)
    }

    @Test("two requests on increasing stream identifiers both decode")
    func twoStreams() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/a")
        wire += get(streamID: 3, path: "/b")

        let events = try connection.receive(wire)
        #expect(events.count == 2)
    }

    @Test("the server preface advertises ENABLE_PUSH = 0 (RFC 9113 §6.5.2)")
    func serverDisablesPush() throws {
        var connection = HTTP2Connection()
        let preface = connection.outboundBytes()
        var settings = HTTP2Settings()  // ENABLE_PUSH defaults to 1; the server frame must clear it
        try preface.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                if frame.header.type == .settings {
                    try frame.payload.withUnsafeBytes { try settings.apply($0.bytes) }
                }
            }
        }
        #expect(settings.enablePush == false)
    }

    // MARK: Failure modes

    @Test("a bad client preface is a PROTOCOL_ERROR")
    func badPreface() {
        var connection = HTTP2Connection()
        var bad = HTTP2ConnectionPreface.client
        bad[0] = 0x47  // 'G'
        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(bad)
        } catch {
            thrown = error.code  // `receive` uses typed throws, so `error` is already an HTTP2Error
        }
        #expect(thrown == .protocolError)
    }

    @Test("a non-increasing stream identifier is a PROTOCOL_ERROR (§5.1.1)")
    func decreasingStreamID() {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 3, path: "/a")
        wire += get(streamID: 1, path: "/b")  // lower than 3 — illegal

        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(wire)
        } catch {
            thrown = error.code  // `receive` uses typed throws, so `error` is already an HTTP2Error
        }
        #expect(thrown == .protocolError)
    }

    @Test("excessive stream resets trigger ENHANCE_YOUR_CALM (Rapid Reset, CVE-2023-44487)")
    func rapidReset() {
        var connection = HTTP2Connection(limits: HTTPLimits(maxStreamResetsPerInterval: 5))
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        var streamID: UInt32 = 1
        for _ in 0..<10 {  // open a stream then immediately reset it, ten times
            wire += openStream(streamID: streamID)
            wire += rstStreamFrame(streamID: streamID)
            streamID += 2
        }
        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(wire)
        } catch {
            thrown = error.code  // `receive` uses typed throws, so `error` is already an HTTP2Error
        }
        #expect(thrown == .enhanceYourCalm)
    }

    @Test("refuses streams beyond SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 §5.1.2)")
    func refusesExcessConcurrentStreams() throws {
        var connection = HTTP2Connection(limits: HTTPLimits(maxConcurrentStreams: 2))
        _ = connection.outboundBytes()  // discard the server SETTINGS preface
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += openStream(streamID: 1)  // opens (no END_STREAM, stays active)
        wire += openStream(streamID: 3)  // opens — now at the cap of 2
        wire += openStream(streamID: 5)  // exceeds the cap — must be refused, not fatal

        let events = try connection.receive(wire)
        #expect(events.isEmpty)  // none completed; the 3rd is refused, the connection survives
        // The server queued RST_STREAM(REFUSED_STREAM) for the excess stream.
        let refused = try firstRstStream(connection.outboundBytes())
        #expect(refused?.streamID == HTTP2StreamID(5))
        #expect(refused?.code == .refusedStream)
    }

    @Test("a stream that depends on itself is reset with PROTOCOL_ERROR (RFC 9113 §5.3.1)")
    func selfDependentStreamReset() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()  // discard the server SETTINGS preface
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += selfDependentHeadersFrame(streamID: 1)

        let events = try connection.receive(wire)
        #expect(events.isEmpty)  // the stream is rejected, not delivered; the connection survives
        let reset = try firstRstStream(connection.outboundBytes())
        #expect(reset?.streamID == HTTP2StreamID(1))
        #expect(reset?.code == .protocolError)
    }

    @Test("a PING flood is ENHANCE_YOUR_CALM (§6.7, clock-free leaky bucket)")
    func pingFlood() throws {
        var connection = HTTP2Connection(limits: HTTPLimits(maxStreamResetsPerInterval: 5))
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        for _ in 0..<10 { wire += pingFrame() }  // ten PINGs, no useful work — a flood

        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(wire)
        } catch {
            thrown = error.code
        }
        #expect(thrown == .enhanceYourCalm)
    }

    // MARK: Response encoding

    @Test("encodes a response (HEADERS + DATA) for a received request")
    func encodesResponse() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()  // discard the server SETTINGS preface

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/")
        let events = try connection.receive(wire)
        _ = connection.outboundBytes()  // discard the SETTINGS ACK

        let event = try #require(events.first)
        guard case .request(let streamID, _, _) = event else {
            Issue.record("expected a request event")
            return
        }

        var response = HTTPResponse(status: .ok)
        _ = response.headerFields.append("text/plain", for: .contentType)
        try connection.respond(to: streamID, response, body: Array("hello".utf8))

        let decoded = try decodeResponse(connection.outboundBytes())
        #expect(decoded.status == "200")
        #expect(decoded.contentType == "text/plain")
        #expect(String(decoding: decoded.body, as: UTF8.self) == "hello")
    }

    // MARK: Performance guards

    @Test("draining outbound bytes allocates nothing — a swap, not a copy-on-write copy")
    func outboundDrainIsZeroAllocation() throws {
        var connection = HTTP2Connection()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        _ = try connection.receive(wire)  // queues a SETTINGS ACK
        _ = connection.outboundBytes()  // warm up: drain once

        // `mallocDelta` reads a PROCESS-WIDE counter, and the test runner executes suites in parallel,
        // so another suite's allocation can land in any one measurement window. Such noise only ever
        // ADDS, so the minimum over several re-prepared trials is the true cost — zero for the swap.
        var measurements: [Int] = []
        for _ in 0..<16 {
            _ = try connection.receive(settingsFrame())  // re-queue a SETTINGS ACK to drain
            if let allocations = mallocDelta({ _ = connection.outboundBytes() }) {
                measurements.append(allocations)
            }
        }
        if let best = measurements.min() {  // nil only where counting is unavailable
            #expect(best == 0)
        }
    }

    // MARK: Flow control (RFC 9113 §6.9)

    @Test("a response larger than the stream send window is deferred until WINDOW_UPDATE")
    func deferredResponseDataAwaitsWindowUpdate() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()  // discard the server SETTINGS preface

        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame(initialWindowSize: 4)  // peer accepts only 4 DATA octets per stream
        wire += get(streamID: 1, path: "/")
        let events = try connection.receive(wire)
        _ = connection.outboundBytes()  // discard the SETTINGS ACK

        let event = try #require(events.first)
        guard case .request(let streamID, _, _) = event else {
            Issue.record("expected a request event")
            return
        }
        try connection.respond(to: streamID, HTTPResponse(status: .ok), body: Array("hello".utf8))

        // Only 4 of the 5 body octets fit the window; that DATA frame must NOT carry END_STREAM yet.
        let first = try collectData(connection.outboundBytes())
        #expect(first.bytes == Array("hell".utf8))
        #expect(!first.endStream)

        // Opening the window releases the final octet, now carrying END_STREAM.
        _ = try connection.receive(windowUpdateFrame(streamID: 1, increment: 10))
        let second = try collectData(connection.outboundBytes())
        #expect(second.bytes == Array("o".utf8))
        #expect(second.endStream)
    }

    @Test("a zero-increment WINDOW_UPDATE is a PROTOCOL_ERROR (RFC 9113 §6.9)")
    func zeroWindowUpdateIsProtocolError() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 1, path: "/")
        _ = try connection.receive(wire)

        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(windowUpdateFrame(streamID: 0, increment: 0))
        } catch {
            thrown = error.code  // `receive` uses typed throws, so `error` is already an HTTP2Error
        }
        #expect(thrown == .protocolError)
    }

    @Test(
        "DATA beyond the advertised stream receive window resets the stream (FLOW_CONTROL_ERROR, §6.9)"
    )
    func inboundStreamWindowEnforced() throws {
        var settings = HTTP2Settings()
        settings.initialWindowSize = 10  // we will accept only 10 DATA octets per stream
        var connection = HTTP2Connection(localSettings: settings)
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += openStream(streamID: 1)  // POST awaiting a body
        _ = try connection.receive(wire)
        _ = connection.outboundBytes()  // discard the SETTINGS ACK

        // 20 octets exceed the 10-octet stream window. RFC 9113 §6.9 lets the receiver answer with a
        // stream error — RST_STREAM(FLOW_CONTROL_ERROR) — so the connection (and its other streams)
        // survives and `receive` does not throw.
        let events = try connection.receive(
            dataFrame(streamID: 1, payload: [UInt8](repeating: 0x61, count: 20), endStream: true))
        #expect(events.isEmpty)
        let reset = try firstRstStream(connection.outboundBytes())
        #expect(reset?.streamID == HTTP2StreamID(1))
        #expect(reset?.code == .flowControlError)
    }

    @Test(
        "a large upload is admitted and the receive window replenished with WINDOW_UPDATEs (§6.9)")
    func inboundUploadReplenished() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += openStream(streamID: 1)  // POST awaiting a body
        _ = try connection.receive(wire)
        _ = connection.outboundBytes()  // discard the SETTINGS ACK

        // 100 KiB across 16 KiB DATA frames — well past the initial 65,535 receive window.
        let chunk = [UInt8](repeating: 0x7a, count: 16_384)
        var events: [HTTP2Connection.Event] = []
        var windowUpdateTotal = 0
        var total = 0
        while total < 100_000 {
            let last = total + chunk.count >= 100_000
            let payload = last ? Array(chunk[0..<(100_000 - total)]) : chunk
            events += try connection.receive(
                dataFrame(streamID: 1, payload: payload, endStream: last))
            windowUpdateTotal += try sumWindowUpdates(connection.outboundBytes())
            total += payload.count
        }

        let event = try #require(events.first)
        guard case .request(_, _, let body) = event else {
            Issue.record("expected a request event")
            return
        }
        #expect(body.count == 100_000)
        #expect(windowUpdateTotal > 0)  // the server replenished its receive window mid-upload
    }

    @Test("a connection error queues a GOAWAY carrying the error code (§6.8)")
    func connectionErrorSendsGoAway() throws {
        var connection = HTTP2Connection()
        _ = connection.outboundBytes()
        var wire = HTTP2ConnectionPreface.client
        wire += settingsFrame()
        wire += get(streamID: 3, path: "/a")
        wire += get(streamID: 1, path: "/b")  // non-increasing → connection PROTOCOL_ERROR

        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(wire)
        } catch {
            thrown = error.code
        }
        #expect(thrown == .protocolError)

        let goAway = try firstGoAway(connection.outboundBytes())
        #expect(goAway?.code == .protocolError)
        #expect(goAway?.lastStreamID == HTTP2StreamID(3))  // last stream we processed
    }

    /// The first GOAWAY frame on the wire (its last-stream-id and decoded error code), if any.
    private func firstGoAway(
        _ bytes: [UInt8]
    ) throws -> (lastStreamID: HTTP2StreamID, code: HTTP2ErrorCode)? {
        var found: (HTTP2StreamID, HTTP2ErrorCode)?
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while found == nil, let frame = try frames.nextFrame(&reader) {
                guard frame.header.type == .goAway, frame.payload.count >= 8 else { continue }
                let lastID =
                    UInt32(frame.payload[0]) << 24 | UInt32(frame.payload[1]) << 16
                    | UInt32(frame.payload[2]) << 8 | UInt32(frame.payload[3])
                let code =
                    UInt32(frame.payload[4]) << 24 | UInt32(frame.payload[5]) << 16
                    | UInt32(frame.payload[6]) << 8 | UInt32(frame.payload[7])
                found = (HTTP2StreamID(rawValue: lastID), HTTP2ErrorCode(code: code))
            }
        }
        return found
    }

    /// The first RST_STREAM frame on the wire (its stream id and decoded error code), if any.
    private func firstRstStream(
        _ bytes: [UInt8]
    ) throws -> (streamID: HTTP2StreamID, code: HTTP2ErrorCode)? {
        var found: (HTTP2StreamID, HTTP2ErrorCode)?
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while found == nil, let frame = try frames.nextFrame(&reader) {
                guard frame.header.type == .rstStream, frame.payload.count == 4 else { continue }
                let code =
                    UInt32(frame.payload[0]) << 24 | UInt32(frame.payload[1]) << 16
                    | UInt32(frame.payload[2]) << 8 | UInt32(frame.payload[3])
                found = (frame.header.streamID, HTTP2ErrorCode(code: code))
            }
        }
        guard let found else { return nil }
        return (streamID: found.0, code: found.1)
    }
}
