//
//  HTTP2FrameDecoderTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for the RFC 9113 §4 incremental frame decoder: pulling complete frames, leaving
//  partial frames buffered, decoding back-to-back frames, and the §4.2 FRAME_SIZE_ERROR.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §4 — frame decoder")
struct HTTP2FrameDecoderTests {

    private func decode(
        _ bytes: [UInt8], maxFrameSize: Int = 16_384
    ) throws
        -> [HTTP2FrameDecoder.Frame]
    {
        let decoder = HTTP2FrameDecoder(maxFrameSize: maxFrameSize)
        return try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            var frames = [HTTP2FrameDecoder.Frame]()
            while let frame = try decoder.nextFrame(&reader) { frames.append(frame) }
            return frames
        }
    }

    private func errorCode(_ bytes: [UInt8], maxFrameSize: Int = 16_384) -> HTTP2ErrorCode? {
        do {
            _ = try decode(bytes, maxFrameSize: maxFrameSize)
            return nil
        } catch let error as HTTP2Error {
            return error.code
        } catch {
            return nil
        }
    }

    @Test("decodes a complete frame, header and payload")
    func decodesFrame() throws {
        // SETTINGS, length 6, stream 0, payload = one MAX_FRAME_SIZE parameter.
        let frames = try decode([0, 0, 6, 4, 0, 0, 0, 0, 0, 0x00, 0x05, 0x00, 0x00, 0x40, 0x00])
        #expect(frames.count == 1)
        #expect(frames.first?.header.type == .settings)
        #expect(frames.first?.payload == [0x00, 0x05, 0x00, 0x00, 0x40, 0x00])
    }

    @Test("decodes two back-to-back frames")
    func decodesTwoFrames() throws {
        let ping: [UInt8] = [0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        let rstStream: [UInt8] = [0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8]  // RST_STREAM stream 1
        let frames = try decode(ping + rstStream)
        #expect(frames.count == 2)
        #expect(frames.first?.header.type == .ping)
        #expect(frames.last?.header.type == .rstStream)
        #expect(frames.last?.header.streamID == HTTP2StreamID(1))
    }

    @Test("returns nothing while the header is incomplete")
    func incompleteHeader() throws {
        #expect(try decode([0, 0, 6, 4]).isEmpty)
    }

    @Test("returns nothing while the payload is incomplete")
    func incompletePayload() throws {
        // The header declares 6 payload octets but only 3 are present.
        #expect(try decode([0, 0, 6, 4, 0, 0, 0, 0, 0, 1, 2, 3]).isEmpty)
    }

    @Test("a payload larger than max frame size is a FRAME_SIZE_ERROR (§4.2)")
    func oversizedFrame() {
        // The header declares length 20000 (0x4E20); the decoder caps at 16,384.
        let header: [UInt8] = [0x00, 0x4E, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        #expect(errorCode(header, maxFrameSize: 16_384) == .frameSizeError)
    }
}
