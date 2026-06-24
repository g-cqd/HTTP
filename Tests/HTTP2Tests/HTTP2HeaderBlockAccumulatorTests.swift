//
//  HTTP2HeaderBlockAccumulatorTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for RFC 9113 §6.10 HEADERS + CONTINUATION assembly: a single END_HEADERS frame,
//  multi-fragment concatenation, the interleaving rules, and the CONTINUATION-flood / size bounds
//  (CVE-2024-27316).
//

import Testing

@testable import HTTP2

@Suite("RFC 9113 §6.10 — header block assembly")
struct HTTP2HeaderBlockAccumulatorTests {
    private func make() -> HTTP2HeaderBlockAccumulator {
        HTTP2HeaderBlockAccumulator(maxContinuationFrames: 4, maxBlockSize: 64)
    }

    private let stream = HTTP2StreamID(1)

    @Test("a HEADERS frame with END_HEADERS is a complete block")
    func singleHeadersFrame() throws {
        var accumulator = make()
        let outcome = try accumulator.begin(
            streamID: stream,
            fragment: [1, 2, 3],
            endHeaders: true
        )
        #expect(outcome == .complete(stream, [1, 2, 3]))
        #expect(accumulator.isExpectingContinuation == false)
    }

    @Test("HEADERS without END_HEADERS awaits CONTINUATION, then concatenates")
    func headersThenContinuations() throws {
        var accumulator = make()
        #expect(
            try accumulator.begin(streamID: stream, fragment: [1, 2], endHeaders: false)
                == .needsContinuation)
        #expect(accumulator.isExpectingContinuation)
        #expect(accumulator.expectedStream == stream)
        #expect(
            try accumulator.append(streamID: stream, fragment: [3, 4], endHeaders: false)
                == .needsContinuation)
        #expect(
            try accumulator.append(streamID: stream, fragment: [5], endHeaders: true)
                == .complete(stream, [1, 2, 3, 4, 5]))
        #expect(accumulator.isExpectingContinuation == false)
    }

    @Test("a CONTINUATION on a different stream is a PROTOCOL_ERROR (§6.10)")
    func continuationWrongStream() throws {
        var accumulator = make()
        _ = try accumulator.begin(streamID: stream, fragment: [1], endHeaders: false)
        #expect(
            errorCode {
                try accumulator.append(streamID: HTTP2StreamID(3), fragment: [2], endHeaders: true)
            } == .protocolError)
    }

    @Test("a CONTINUATION without an open block is a PROTOCOL_ERROR (§6.10)")
    func continuationWithoutHeaders() {
        var accumulator = make()
        #expect(
            errorCode { try accumulator.append(streamID: stream, fragment: [1], endHeaders: true) }
                == .protocolError)
    }

    @Test("too many CONTINUATION frames is ENHANCE_YOUR_CALM (CVE-2024-27316)")
    func continuationFlood() throws {
        var accumulator = make()  // cap is 4 CONTINUATION frames
        _ = try accumulator.begin(streamID: stream, fragment: [], endHeaders: false)
        for _ in 0 ..< 4 {
            _ = try accumulator.append(streamID: stream, fragment: [0], endHeaders: false)
        }
        #expect(
            errorCode { try accumulator.append(streamID: stream, fragment: [0], endHeaders: true) }
                == .enhanceYourCalm)
    }

    @Test("a header block past the size bound is rejected")
    func blockTooLarge() {
        var accumulator = make()  // bound is 64 octets
        let big = [UInt8](repeating: 0, count: 65)
        #expect(
            errorCode {
                _ = try accumulator.begin(streamID: stream, fragment: big, endHeaders: true)
            } == .enhanceYourCalm)
    }

    private func errorCode<T>(_ body: () throws -> T) -> HTTP2ErrorCode? {
        do {
            _ = try body()
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
