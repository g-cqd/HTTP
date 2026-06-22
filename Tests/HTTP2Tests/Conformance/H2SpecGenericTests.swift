//
//  H2SpecGenericTests.swift
//  HTTP2Tests
//
//  h2spec conformance — the `generic` group (lenient functional checks), parts 1–4: §1 starting
//  HTTP/2, §2 streams & multiplexing, §3 frame definitions, §4 HTTP message exchanges. Unlike the
//  strict `http2` group, these assert the engine *accepts* well-formed input — no RST_STREAM/GOAWAY
//  is queued, and request frames complete into a `.request` event. (The §5 HPACK-representation
//  acceptance checks live in H2SpecGenericHPACKTests.swift.)
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("h2spec generic §1–4 — frames & message exchanges accepted")
struct H2SpecGenericTests {

    // MARK: §1 Starting HTTP/2

    @Test("generic 1/1 — accepts the client connection preface")
    func acceptsClientPreface() throws {
        var connection = try H2Wire.handshaked()  // preface + SETTINGS handshake completes
        H2Wire.expectRequest(H2Wire.get(streamID: 1), on: &connection)
    }

    // MARK: §2 Streams & Multiplexing + §3.3 PRIORITY — PRIORITY is accepted in any stream state

    @Test(
        "generic 2,3.3 — a PRIORITY frame is accepted (idle / weighted / dependent / exclusive)",
        arguments: [
            (label: "idle stream", frame: H2Wire.priority(streamID: 1, dependency: 0)),
            (label: "weight 1", frame: H2Wire.priority(streamID: 1, dependency: 0, weight: 0)),
            (label: "weight 256", frame: H2Wire.priority(streamID: 1, dependency: 0, weight: 255)),
            (label: "stream dependency", frame: H2Wire.priority(streamID: 1, dependency: 3)),
            (
                label: "exclusive",
                frame: H2Wire.priority(streamID: 1, dependency: 0, exclusive: true)
            ),
        ])
    func priorityFrameAccepted(_ testCase: (label: String, frame: [UInt8])) throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectAccepted(testCase.frame, on: &connection)
    }

    // MARK: §3.5/3.7/3.8/3.9 — connection-level control frames accepted on a fresh connection

    @Test(
        "generic 3 — a connection-level control frame is accepted (SETTINGS/PING/GOAWAY/WINDOW_UPDATE)",
        arguments: [
            (label: "SETTINGS", frame: H2Wire.settings()),
            (label: "PING", frame: H2Wire.ping()),
            (label: "GOAWAY", frame: H2Wire.goAway()),
            (
                label: "WINDOW_UPDATE stream 0",
                frame: H2Wire.windowUpdate(streamID: 0, increment: 1)
            ),
        ])
    func controlFrameAccepted(_ testCase: (label: String, frame: [UInt8])) throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectAccepted(testCase.frame, on: &connection)
    }

    // MARK: §2 — frames accepted on a half-closed (remote) stream

    @Test(
        "generic 2 — a frame is accepted on a half-closed (remote) stream (WINDOW_UPDATE/PRIORITY/RST)",
        arguments: [
            (label: "WINDOW_UPDATE", frame: H2Wire.windowUpdate(streamID: 1, increment: 1)),
            (label: "PRIORITY", frame: H2Wire.priority(streamID: 1, dependency: 0)),
            (label: "RST_STREAM", frame: H2Wire.rstStream(streamID: 1)),
        ])
    func frameAcceptedOnHalfClosedRemoteStream(_ testCase: (label: String, frame: [UInt8])) throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.get(streamID: 1))  // END_STREAM → half-closed (remote)
        _ = connection.outboundBytes()
        H2Wire.expectAccepted(testCase.frame, on: &connection)
    }

    // MARK: §3.4 RST_STREAM + §3.9 WINDOW_UPDATE — accepted on an open stream

    @Test(
        "generic 3.4,3.9 — RST_STREAM / WINDOW_UPDATE on an open (stream 1) stream is accepted",
        arguments: [
            (label: "RST_STREAM", frame: H2Wire.rstStream(streamID: 1)),
            (
                label: "WINDOW_UPDATE stream 1",
                frame: H2Wire.windowUpdate(streamID: 1, increment: 1)
            ),
        ])
    func frameAcceptedOnOpenStream(_ testCase: (label: String, frame: [UInt8])) throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.openStream(streamID: 1))  // open, awaiting body
        _ = connection.outboundBytes()
        H2Wire.expectAccepted(testCase.frame, on: &connection)
    }

    @Test("generic 2/5 — a PRIORITY frame on a closed stream is accepted")
    func priorityOnClosedStreamAccepted() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.rstStream(streamID: 1)  // close the stream
        _ = try connection.receive(wire)
        _ = connection.outboundBytes()
        H2Wire.expectAccepted(H2Wire.priority(streamID: 1, dependency: 0), on: &connection)
    }

    // MARK: §3.1 DATA

    @Test("generic 3.1/1 — a DATA frame is accepted")
    func acceptsDataFrame() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.data(streamID: 1, payload: Array("hello".utf8), endStream: true)
        let event = H2Wire.expectRequest(wire, on: &connection)
        if case .request(_, _, let body) = event { #expect(body == Array("hello".utf8)) }
    }

    @Test("generic 3.1/2 — multiple DATA frames are accepted")
    func acceptsMultipleDataFrames() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.data(streamID: 1, payload: Array("foo".utf8), endStream: false)
        wire += H2Wire.data(streamID: 1, payload: Array("bar".utf8), endStream: true)
        let event = H2Wire.expectRequest(wire, on: &connection)
        if case .request(_, _, let body) = event { #expect(body == Array("foobar".utf8)) }
    }

    @Test("generic 3.1/3 — a DATA frame with padding is accepted")
    func acceptsPaddedDataFrame() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        // PADDED: pad-length octet 2, body "ab", then 2 padding octets.
        wire += H2Wire.frame(
            .data, flags: [.padded, .endStream], streamID: 1, payload: [2, 0x61, 0x62, 0, 0])
        let event = H2Wire.expectRequest(wire, on: &connection)
        if case .request(_, _, let body) = event { #expect(body == Array("ab".utf8)) }
    }

    // MARK: §3.2 HEADERS

    @Test(
        "generic 3.2 — a HEADERS frame is accepted (plain / padded / with priority)",
        arguments: [
            (label: "plain", frame: H2Wire.get(streamID: 1)),
            (
                label: "padded",
                frame: H2Wire.headers(streamID: 1, fields: H2Wire.requestFields(), padding: 4)
            ),
            (
                label: "with priority",
                frame: H2Wire.headers(
                    streamID: 1, fields: H2Wire.requestFields(),
                    priority: (exclusive: false, dependency: 0, weight: 0))
            ),
        ])
    func acceptsHeadersFrame(_ testCase: (label: String, frame: [UInt8])) throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectRequest(testCase.frame, on: &connection)
    }

    // MARK: §3.10 CONTINUATION

    @Test("generic 3.10/1 — a HEADERS followed by a CONTINUATION frame is accepted")
    func acceptsContinuationFrame() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1, fields: H2Wire.requestFields(), endStream: true, endHeaders: false)
        wire += H2Wire.continuation(streamID: 1, endHeaders: true)
        H2Wire.expectRequest(wire, on: &connection)
    }

    @Test("generic 3.10/2 — multiple CONTINUATION frames are accepted")
    func acceptsMultipleContinuationFrames() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1, fields: H2Wire.requestFields(), endStream: true, endHeaders: false)
        wire += H2Wire.continuation(streamID: 1, endHeaders: false)
        wire += H2Wire.continuation(streamID: 1, endHeaders: true)
        H2Wire.expectRequest(wire, on: &connection)
    }

    @Test("generic 3.3/5 — a PRIORITY for an idle stream then a HEADERS for a lower id is answered")
    func priorityThenLowerHeadersIsAnswered() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.priority(streamID: 3, dependency: 0)  // PRIORITY does not open stream 3
        wire += H2Wire.get(streamID: 1)  // a later, lower id is still valid
        H2Wire.expectRequest(wire, on: &connection)
    }

    // MARK: §4 HTTP Message Exchanges

    @Test(
        "generic 4 — a request is answered (GET / HEAD)",
        arguments: ["GET", "HEAD"])
    func acceptsSimpleRequest(_ method: String) throws {
        var connection = try H2Wire.handshaked()
        let wire = H2Wire.headers(streamID: 1, fields: H2Wire.requestFields(method: method))
        H2Wire.expectRequest(wire, on: &connection)
    }

    @Test("generic 4/3 — a POST request with a body is answered")
    func acceptsPostRequest() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.data(streamID: 1, payload: Array("body".utf8), endStream: true)
        H2Wire.expectRequest(wire, on: &connection)
    }

    @Test("generic 4/4 — a POST request with trailers is answered")
    func acceptsPostWithTrailers() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.data(streamID: 1, payload: Array("body".utf8), endStream: false)
        wire += H2Wire.headers(
            streamID: 1, fields: [HPACKField(name: "x-trace", value: "1")], endStream: true)
        H2Wire.expectRequest(wire, on: &connection)
    }

    // h2spec coverage: §1 (1) + §2 (5) + §3.1 (3) + §3.2 (3) + §3.3 (5) + §3.4 (1) + §3.5 (1)
    //                  + §3.7 (1) + §3.8 (1) + §3.9 (2) + §3.10 (2) + §4 (4) = 29 cases.
    //                  (§5 HPACK = 15 cases, in H2SpecGenericHPACKTests.swift → generic total 44.)
}
