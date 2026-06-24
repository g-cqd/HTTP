//
//  H2SpecFrameFormatTests.swift
//  HTTP2Tests
//
//  h2spec conformance — the `http2` group, RFC 7540/9113 §4 (HTTP Frames): §4.1 Frame Format,
//  §4.2 Frame Size, and §4.3 Header Compression and Decompression. Each `@Test` quotes the h2spec
//  case description verbatim and cites the RFC §. Driven against the sans-I/O `HTTP2Connection`:
//  feed crafted octets, assert the connection- or stream-scoped reaction.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("h2spec http2 §4 — HTTP Frames")
struct H2SpecFrameFormatTests {
    // MARK: §4.1 Frame Format

    @Test("4.1/1 — sends a frame with unknown type; MUST be ignored and discarded (RFC 9113 §4.1)")
    func unknownFrameTypeIsIgnored() throws {
        var connection = try H2Wire.handshaked()
        // A type the engine does not define (0xFF) must be ignored, leaving the connection usable.
        H2Wire.expectAccepted(
            H2Wire.frame(HTTP2FrameType(rawValue: 0xFF), payload: [1, 2, 3]),
            on: &connection)
        H2Wire.expectRequest(H2Wire.get(streamID: 1), on: &connection)
    }

    @Test("4.1/2 — sends a frame with an undefined flag; MUST be ignored (RFC 9113 §4.1)")
    func undefinedFlagIsIgnored() throws {
        var connection = try H2Wire.handshaked()
        // A GET whose HEADERS carries an undefined flag bit (0x10) alongside END_STREAM|END_HEADERS
        // must still complete: undefined flags are ignored, not rejected.
        var wire = H2Wire.get(streamID: 1)
        wire[4] |= 0x10  // the flags octet is index 4 of the 9-octet header
        H2Wire.expectRequest(wire, on: &connection)
    }

    @Test("4.1/3 — sends a frame with a reserved field bit set; MUST be ignored (RFC 9113 §4.1)")
    func reservedBitIsIgnored() throws {
        var connection = try H2Wire.handshaked()
        // Set the reserved high bit of the 31-bit stream identifier (header octet 5); a receiver MUST
        // ignore it, so the frame is still stream 1 and the request completes.
        var wire = H2Wire.get(streamID: 1)
        wire[5] |= 0x80
        H2Wire.expectRequest(wire, on: &connection)
    }

    // MARK: §4.2 Frame Size

    @Test("4.2/1 — sends a DATA frame with 2^14 octets; MUST be received (RFC 9113 §4.2)")
    func acceptsMaximumSizeDataFrame() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.data(
            streamID: 1, payload: [UInt8](repeating: 0x61, count: 16_384),
            endStream: true)
        let event = H2Wire.expectRequest(wire, on: &connection)
        if case .request(_, _, let body) = event { #expect(body.count == 16_384) }
    }

    @Test(
        "4.2/2 — sends a DATA frame exceeding SETTINGS_MAX_FRAME_SIZE; MUST be FRAME_SIZE_ERROR (§4.2)"
    )
    func oversizedDataFrameIsFrameSizeError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.data(
            streamID: 1, payload: [UInt8](repeating: 0x61, count: 16_385),
            endStream: true)
        H2Wire.expectConnectionError(.frameSizeError, feeding: wire, on: &connection)
    }

    @Test(
        "4.2/3 — sends a HEADERS frame exceeding SETTINGS_MAX_FRAME_SIZE; MUST be FRAME_SIZE_ERROR (§4.2)"
    )
    func oversizedHeadersFrameIsFrameSizeError() throws {
        var connection = try H2Wire.handshaked()
        // A single oversized field value pushes the encoded block past the 16,384-octet frame cap.
        let huge = HPACKField(name: "x-big", value: String(repeating: "a", count: 30_000))
        let wire = H2Wire.headers(streamID: 1, fields: H2Wire.requestFields(extra: [huge]))
        H2Wire.expectConnectionError(.frameSizeError, feeding: wire, on: &connection)
    }

    // MARK: §4.3 Header Compression and Decompression

    @Test(
        "4.3/1 — sends an invalid header block fragment; MUST be COMPRESSION_ERROR (RFC 9113 §4.3)")
    func invalidHeaderBlockIsCompressionError() throws {
        var connection = try H2Wire.handshaked()
        // 0x80 is an indexed header field at index 0 — an HPACK decoding error (RFC 7541 §6.1) the
        // engine surfaces as a connection COMPRESSION_ERROR.
        let wire = H2Wire.frame(
            .headers, flags: [.endHeaders, .endStream], streamID: 1,
            payload: [0x80])
        H2Wire.expectConnectionError(.compressionError, feeding: wire, on: &connection)
    }

    @Test(
        "4.3/2 — sends a PRIORITY frame while sending the header blocks; MUST be PROTOCOL_ERROR (§4.3)"
    )
    func priorityInterleavedInHeaderBlockIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1, fields: H2Wire.requestFields(), endStream: false,
            endHeaders: false)  // opens a block awaiting CONTINUATION
        // Interleaving anything other than CONTINUATION on the open block is illegal.
        wire += H2Wire.priority(streamID: 1, dependency: 0)
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    @Test(
        "4.3/3 — sends a HEADERS frame to another stream while sending header blocks; PROTOCOL_ERROR (§4.3)"
    )
    func headersForAnotherStreamInHeaderBlockIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1, fields: H2Wire.requestFields(), endStream: false,
            endHeaders: false)
        // A HEADERS for a different stream while the block is open is illegal (must be CONTINUATION).
        wire += H2Wire.headers(streamID: 3, fields: H2Wire.requestFields())
        H2Wire.expectConnectionError(.protocolError, feeding: wire, on: &connection)
    }

    // h2spec coverage: §4.1 (3) + §4.2 (3) + §4.3 (3) = 9 cases.
}
