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
import Testing

@testable import HTTP2

@Suite("RFC 9113 — connection engine")
struct HTTP2ConnectionTests {

    // MARK: Wire builders

    private func settingsFrame() -> [UInt8] {
        var out = [UInt8]()
        HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection).encode(
            into: &out)
        return out
    }

    private func headersFrame(streamID: UInt32, fields: [HPACKField], endStream: Bool) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
        let block = encoder.encode(fields)
        var flags: HTTP2FrameFlags = [.endHeaders]
        if endStream { flags.insert(.endStream) }
        var out = [UInt8]()
        HTTP2FrameHeader(
            payloadLength: block.count, type: .headers, flags: flags,
            streamID: HTTP2StreamID(streamID)
        ).encode(into: &out)
        out.append(contentsOf: block)
        return out
    }

    private func dataFrame(streamID: UInt32, payload: [UInt8], endStream: Bool) -> [UInt8] {
        var out = [UInt8]()
        HTTP2FrameHeader(
            payloadLength: payload.count, type: .data, flags: endStream ? [.endStream] : [],
            streamID: HTTP2StreamID(streamID)
        ).encode(into: &out)
        out.append(contentsOf: payload)
        return out
    }

    private func get(streamID: UInt32, path: String) -> [UInt8] {
        headersFrame(
            streamID: streamID,
            fields: [
                HPACKField(name: ":method", value: "GET"),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: path),
                HPACKField(name: ":authority", value: "example.com"),
            ], endStream: true)
    }

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

    // MARK: Failure modes

    @Test("a bad client preface is a PROTOCOL_ERROR")
    func badPreface() {
        var connection = HTTP2Connection()
        var bad = HTTP2ConnectionPreface.client
        bad[0] = 0x47  // 'G'
        var thrown: HTTP2ErrorCode?
        do {
            _ = try connection.receive(bad)
        } catch let error as HTTP2Error {
            thrown = error.code
        } catch {}
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
        } catch let error as HTTP2Error {
            thrown = error.code
        } catch {}
        #expect(thrown == .protocolError)
    }
}
