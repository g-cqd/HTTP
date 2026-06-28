//
//  HTTP2StreamTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for the RFC 9113 §5.1 stream state machine: the request/response lifecycle and
//  the state-scoped error rules (idle/trailers → connection PROTOCOL_ERROR, closed → stream
//  STREAM_CLOSED).
//

import Testing

@testable import HTTP2

@Suite("RFC 9113 §5.1 — stream state machine")
struct HTTP2StreamTests {
    private func stream() -> HTTP2Stream { HTTP2Stream(id: HTTP2StreamID(1)) }

    @Test("idle → open on HEADERS without END_STREAM")
    func opensOnHeaders() throws {
        var subject = stream()
        try subject.receiveHeaders(endStream: false)
        #expect(subject.state == .open)
    }

    @Test("idle → half-closed (remote) on HEADERS with END_STREAM")
    func headersEndStream() throws {
        var subject = stream()
        try subject.receiveHeaders(endStream: true)
        #expect(subject.state == .halfClosedRemote)
    }

    @Test("a full request/response lifecycle reaches closed")
    func fullLifecycle() throws {
        var subject = stream()
        try subject.receiveHeaders(endStream: false)  // request headers → open
        try subject.receiveData(endStream: true)  // request body ends → half-closed (remote)
        #expect(subject.state == .halfClosedRemote)
        try subject.sendHeaders(endStream: false)  // response headers
        try subject.sendData(endStream: true)  // response body ends → closed
        #expect(subject.state == .closed)
    }

    @Test("DATA before HEADERS is a connection PROTOCOL_ERROR (§5.1)")
    func dataBeforeHeaders() {
        var subject = stream()
        #expect(errorCode { try subject.receiveData(endStream: false) } == .protocolError)
    }

    @Test("a frame on a closed stream is a STREAM_CLOSED stream error (§5.1)")
    func frameOnClosedStream() {
        var subject = HTTP2Stream(id: HTTP2StreamID(1), state: .closed)
        #expect(errorCode { try subject.receiveData(endStream: false) } == .streamClosed)
        #expect(errorCode { try subject.receiveHeaders(endStream: false) } == .streamClosed)
    }

    @Test("trailers without END_STREAM are a PROTOCOL_ERROR (§5.1)")
    func trailersMustEndStream() throws {
        var subject = stream()
        try subject.receiveHeaders(endStream: false)  // → open
        #expect(errorCode { try subject.receiveHeaders(endStream: false) } == .protocolError)
    }

    private func errorCode(_ body: () throws -> Void) -> HTTP2ErrorCode? {
        do {
            try body()
            return nil
        }
        catch let error as HTTP2Error {
            return error.code
        }
        catch {
            return nil
        }
    }
}
