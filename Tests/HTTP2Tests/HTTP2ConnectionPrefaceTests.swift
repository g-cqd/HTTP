//
//  HTTP2ConnectionPrefaceTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for the RFC 9113 §3.4 client connection preface: matching and consuming the full
//  magic, leaving a valid-but-short prefix buffered, and rejecting a mismatch.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §3.4 — connection preface")
struct HTTP2ConnectionPrefaceTests {

    private func consume(_ bytes: [UInt8]) throws -> (HTTP2ConnectionPreface.MatchResult, Int) {
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let result = try HTTP2ConnectionPreface.consume(&reader)
            return (result, reader.position)
        }
    }

    private func errorCode(_ bytes: [UInt8]) -> HTTP2ErrorCode? {
        do {
            _ = try consume(bytes)
            return nil
        } catch let error as HTTP2Error {
            return error.code
        } catch {
            return nil
        }
    }

    @Test("consumes the full 24-octet client preface")
    func matchesFull() throws {
        let (result, consumed) = try consume(HTTP2ConnectionPreface.client)
        #expect(result == .matched)
        #expect(consumed == 24)
    }

    @Test("a valid but short prefix is incomplete and consumes nothing")
    func incompletePrefix() throws {
        let (result, consumed) = try consume(Array(HTTP2ConnectionPreface.client.prefix(10)))
        #expect(result == .incomplete)
        #expect(consumed == 0)
    }

    @Test("a mismatching octet is a PROTOCOL_ERROR")
    func mismatch() {
        var bytes = HTTP2ConnectionPreface.client
        bytes[0] = 0x47  // 'G', as if an HTTP/1.1 GET arrived on an h2 connection
        #expect(errorCode(bytes) == .protocolError)
    }
}
