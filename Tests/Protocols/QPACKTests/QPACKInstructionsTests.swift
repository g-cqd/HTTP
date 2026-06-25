//
//  QPACKInstructionsTests.swift
//  QPACKTests
//
//  RED→GREEN driver for the RFC 9204 §4.3/§4.4 instruction-stream parsers with the dynamic table
//  disabled: the encoder-stream violations (over-capacity set / any insert / duplicate →
//  QPACK_ENCODER_STREAM_ERROR), the decoder-stream violations (Insert Count Increment / Section
//  Acknowledgment → QPACK_DECODER_STREAM_ERROR), the benign cases that are consumed or awaited, and the
//  stub generators that owe nothing.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 §4.3/§4.4 — QPACK instruction streams")
struct QPACKInstructionsTests {
    private func parseEncoder(
        _ bytes: [UInt8], maxCapacity: Int = 0
    ) -> (error: QPACKError?, consumed: Int) {
        bytes.withUnsafeBytes { raw -> (error: QPACKError?, consumed: Int) in
            var reader = ByteReader(raw)
            do {
                try QPACKInstructions.parseEncoderStream(&reader, maxCapacity: maxCapacity)
                return (nil, reader.position)
            }
            catch {
                return (error as? QPACKError, reader.position)
            }
        }
    }

    private func parseDecoder(_ bytes: [UInt8]) -> (error: QPACKError?, consumed: Int) {
        bytes.withUnsafeBytes { raw -> (error: QPACKError?, consumed: Int) in
            var reader = ByteReader(raw)
            do {
                try QPACKInstructions.parseDecoderStream(&reader)
                return (nil, reader.position)
            }
            catch {
                return (error as? QPACKError, reader.position)
            }
        }
    }

    @Test(
        "encoder-stream violations are QPACK_ENCODER_STREAM_ERROR (RFC 9204 §4.3)",
        arguments: [
            (label: "Set Dynamic Table Capacity above the limit (5)", bytes: [0x25] as [UInt8]),
            (label: "insert with name reference (0x80)", bytes: [0x80]),
            (label: "insert with literal name (0x40)", bytes: [0x40]),
            (label: "duplicate (0x00)", bytes: [0x00])
        ] as [(label: String, bytes: [UInt8])])
    func encoderStreamViolations(_ testCase: (label: String, bytes: [UInt8])) {
        #expect(parseEncoder(testCase.bytes).error?.code == .encoderStreamError)
    }

    @Test("a Set Dynamic Table Capacity of 0 is accepted (within the limit)")
    func setCapacityZeroAccepted() {
        let result = parseEncoder([0x20])  // 001 00000 → capacity 0
        #expect(result.error == nil)
        #expect(result.consumed == 1)
    }

    @Test("an empty encoder stream consumes nothing and is no error")
    func emptyEncoderStream() {
        let result = parseEncoder([])
        #expect(result.error == nil)
        #expect(result.consumed == 0)
    }

    @Test("a truncated Set Capacity is left unconsumed for the next call")
    func truncatedSetCapacity() {
        // 0x3F = 001 11111: a 5-bit prefix that demands a continuation octet that never arrives.
        let result = parseEncoder([0x3F])
        #expect(result.error == nil)
        #expect(result.consumed == 0)
    }

    @Test(
        "decoder-stream violations are QPACK_DECODER_STREAM_ERROR (RFC 9204 §4.4)",
        arguments: [
            (label: "Section Acknowledgment (0x81)", bytes: [0x81] as [UInt8]),
            (label: "Insert Count Increment of 0 (0x00)", bytes: [0x00]),
            (label: "Insert Count Increment beyond what was sent (5)", bytes: [0x05])
        ] as [(label: String, bytes: [UInt8])])
    func decoderStreamViolations(_ testCase: (label: String, bytes: [UInt8])) {
        #expect(parseDecoder(testCase.bytes).error?.code == .decoderStreamError)
    }

    @Test("a Stream Cancellation is consumed and ignored (RFC 9204 §4.4.2)")
    func streamCancellationIgnored() {
        let result = parseDecoder([0x41])  // 01 000001 → cancel stream 1
        #expect(result.error == nil)
        #expect(result.consumed == 1)
    }

    @Test("a truncated Stream Cancellation is left unconsumed for the next call")
    func truncatedStreamCancellation() {
        // 0x7F = 01 111111: a 6-bit prefix demanding a continuation octet that never arrives.
        let result = parseDecoder([0x7F])
        #expect(result.error == nil)
        #expect(result.consumed == 0)
    }

    @Test("the generators owe nothing at capacity 0")
    func generatorsAreEmpty() {
        #expect(QPACKInstructions.encoderStreamOutput().isEmpty)
        #expect(QPACKInstructions.decoderStreamOutput().isEmpty)
    }
}
