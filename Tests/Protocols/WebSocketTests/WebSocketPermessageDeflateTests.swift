//
//  WebSocketPermessageDeflateTests.swift
//  WebSocketTests
//
//  RFC 7692 — permessage-deflate over the zlib shim. Covers the bit-exact codec round-trip (with and
//  without context-takeover), the connection engine's compress-on-send / inflate-on-receive with RSV1,
//  the framing rules (RSV1 only when negotiated and only on a message's first frame), and the CWE-409
//  decompression-bomb cap. Fixtures build masked client frames (RFC 6455 §5.1/§5.3) of any length, with
//  an optional RSV1 bit.
//

import HTTPCore
import Testing

@testable import WebSocket

@Suite("RFC 7692 — WebSocket permessage-deflate")
struct WebSocketPermessageDeflateTests {
    /// A fresh codec with the given parameters (context-takeover by default).
    private func makeCodec(
        _ parameters: PermessageDeflateParameters = .init()
    ) throws -> PermessageDeflate {
        try #require(PermessageDeflate(parameters: parameters))
    }

    // MARK: Codec round-trip

    @Test(
        "compress then decompress round-trips a single message (RFC 7692 §7.2)",
        arguments: [
            (label: "text", message: Array("Hello hello hello, permessage-deflate!".utf8)),
            (label: "binary", message: (0 ..< 512).map { UInt8($0 & 0xFF) }),
            (label: "empty", message: [UInt8]()),
            (label: "repetitive", message: [UInt8](repeating: 0x61, count: 50_000))
        ] as [(label: String, message: [UInt8])])
    func codecRoundTrips(_ probe: (label: String, message: [UInt8])) throws {
        let codec = try makeCodec()
        let compressed = try #require(codec.compress(probe.message))
        #expect(codec.decompress(compressed, maxSize: 1 << 20) == probe.message)
    }

    @Test("context-takeover compresses a repeated message against history (RFC 7692 §7.1.1)")
    func contextTakeoverRoundTrips() throws {
        // A sender codec compresses a sequence; a receiver codec inflates it *in order*, rebuilding the
        // matching LZ77 window. The repeated second message must compress smaller than the first.
        let sender = try makeCodec()
        let receiver = try makeCodec()
        let phrase = Array("the quick brown fox jumps over the lazy dog".utf8)
        let first = try #require(sender.compress(phrase))
        #expect(receiver.decompress(first, maxSize: 1 << 20) == phrase)
        let second = try #require(sender.compress(phrase))
        #expect(receiver.decompress(second, maxSize: 1 << 20) == phrase)
        #expect(second.count < first.count)  // the window carried over (context-takeover)
    }

    @Test("no_context_takeover resets per message, so messages decode independently (§7.1.1)")
    func noContextTakeoverIndependent() throws {
        let params = PermessageDeflateParameters(
            serverNoContextTakeover: true, clientNoContextTakeover: true
        )
        let sender = try makeCodec(params)
        let receiver = try makeCodec(params)
        let first = try #require(sender.compress(Array("alpha alpha alpha".utf8)))
        let second = try #require(sender.compress(Array("alpha alpha alpha".utf8)))
        #expect(first == second)  // each message is independent — identical input, identical output
        // Decompress out of order: each reset makes that valid.
        #expect(receiver.decompress(second, maxSize: 1 << 20) == Array("alpha alpha alpha".utf8))
        #expect(receiver.decompress(first, maxSize: 1 << 20) == Array("alpha alpha alpha".utf8))
    }

    // MARK: Engine receive / send

    @Test("a negotiated connection inflates a compressed (RSV1) text message (RFC 7692 §7.2.2)")
    func receivesCompressedText() throws {
        let message = Array("permessage-deflate hello hello hello".utf8)
        let compressed = try #require(makeCodec().compress(message))
        var connection = WebSocketConnection(permessageDeflate: PermessageDeflateParameters())
        let events = try connection.receive(clientFrame(.text, compressed, rsv1: true))
        #expect(events == [.message(opcode: .text, payload: message)])
    }

    @Test("a negotiated connection compresses an outbound message with RSV1 set (RFC 7692 §6)")
    func sendsCompressedWithRSV1() throws {
        var connection = WebSocketConnection(permessageDeflate: PermessageDeflateParameters())
        connection.send(text: "hello hello hello hello")
        let frame = try #require(serverFrames(connection.outboundBytes()).first)
        #expect(frame.rsv1)
        let codec = try makeCodec()
        let expected = Array("hello hello hello hello".utf8)
        #expect(codec.decompress(frame.payload, maxSize: 1 << 20) == expected)
    }

    @Test("a compressed binary message round-trips end-to-end through two engines")
    func endToEndBinary() throws {
        let message = (0 ..< 300).map { UInt8(($0 * 7) & 0xFF) }
        var sender = WebSocketConnection(permessageDeflate: PermessageDeflateParameters())
        sender.send(binary: message)
        let frame = try #require(serverFrames(sender.outboundBytes()).first)
        var receiver = WebSocketConnection(permessageDeflate: PermessageDeflateParameters())
        let events = try receiver.receive(clientFrame(.binary, frame.payload, rsv1: frame.rsv1))
        #expect(events == [.message(opcode: .binary, payload: message)])
    }

    @Test("an uncompressed (RSV1-clear) frame is still accepted on a negotiated connection (§6)")
    func acceptsUncompressedWhenNegotiated() throws {
        var connection = WebSocketConnection(permessageDeflate: PermessageDeflateParameters())
        let events = try connection.receive(clientFrame(.text, Array("plain".utf8), rsv1: false))
        #expect(events == [.message(opcode: .text, payload: Array("plain".utf8))])
    }

    // MARK: Framing rules

    @Test("RSV1 without a negotiated extension is rejected (RFC 7692 §6 / RFC 6455 §5.2)")
    func rsv1WithoutNegotiationRejected() {
        var connection = WebSocketConnection()  // permessage-deflate off
        var thrown: WebSocketError?
        do { _ = try connection.receive(clientFrame(.text, [0x00], rsv1: true)) }
        catch { thrown = error }
        #expect(thrown == .reservedBitsSet)
    }

    @Test("RSV1 on a continuation frame is rejected (only the first frame carries it, RFC 7692 §6)")
    func rsv1OnContinuationRejected() throws {
        let compressed = try #require(makeCodec().compress(Array("compressed".utf8)))
        var connection = WebSocketConnection(permessageDeflate: PermessageDeflateParameters())
        var wire = clientFrame(.text, Array(compressed.prefix(2)), fin: false, rsv1: true)
        wire += clientFrame(.continuation, Array(compressed.dropFirst(2)), fin: true, rsv1: true)
        var thrown: WebSocketError?
        do { _ = try connection.receive(wire) }
        catch { thrown = error }
        #expect(thrown == .reservedBitsSet)
    }

    @Test("RSV1 on a control frame is rejected — control frames are never compressed (RFC 7692 §6)")
    func rsv1OnControlFrameRejected() {
        var connection = WebSocketConnection(permessageDeflate: PermessageDeflateParameters())
        var thrown: WebSocketError?
        do { _ = try connection.receive(clientFrame(.ping, [0x01], rsv1: true)) }
        catch { thrown = error }
        #expect(thrown == .reservedBitsSet)
    }

    // MARK: Decompression bomb (CWE-409)

    @Test("a decompression bomb past the message cap closes the connection (CWE-409)")
    func decompressionBombCapped() throws {
        let bomb = [UInt8](repeating: 0, count: 256 << 10)  // 256 KiB of zeros → tiny compressed
        let compressed = try #require(makeCodec().compress(bomb))
        var connection = WebSocketConnection(
            maxMessageSize: 4 << 10, permessageDeflate: PermessageDeflateParameters()
        )
        var thrown: WebSocketError?
        do { _ = try connection.receive(clientFrame(.binary, compressed, rsv1: true)) }
        catch { thrown = error }
        #expect(thrown == .invalidCompressedData)
        #expect(connection.isClosing)
    }

    @Test("malformed compressed data is rejected (RFC 7692 §7.2.2)")
    func malformedCompressedRejected() {
        var connection = WebSocketConnection(permessageDeflate: PermessageDeflateParameters())
        var thrown: WebSocketError?
        // BTYPE=11 is a reserved/invalid DEFLATE block type (RFC 1951 §3.2.3); zlib rejects it.
        do { _ = try connection.receive(clientFrame(.binary, [0x06, 0xDE, 0xAD], rsv1: true)) }
        catch { thrown = error }
        #expect(thrown == .invalidCompressedData)
    }

    // MARK: Fixtures

    /// A masked client frame (RFC 6455 §5.1/§5.3) of any length, with an optional RSV1 bit (RFC 7692).
    private func clientFrame(
        _ opcode: WebSocketOpcode,
        _ payload: [UInt8],
        fin: Bool = true,
        rsv1: Bool = false
    ) -> [UInt8] {
        let key: [UInt8] = [0x12, 0x34, 0x56, 0x78]
        var wire: [UInt8] = [(fin ? 0x80 : 0) | (rsv1 ? 0x40 : 0) | opcode.rawValue]
        if payload.count <= 125 {
            wire.append(0x80 | UInt8(payload.count))
        }
        else if payload.count <= 0xFFFF {
            wire.append(0x80 | 126)
            wire.append(UInt8(truncatingIfNeeded: payload.count >> 8))
            wire.append(UInt8(truncatingIfNeeded: payload.count))
        }
        else {
            wire.append(0x80 | 127)
            for shift in stride(from: 56, through: 0, by: -8) {
                wire.append(UInt8(truncatingIfNeeded: payload.count >> shift))
            }
        }
        wire += key
        for (index, byte) in payload.enumerated() { wire.append(byte ^ key[index & 0x3]) }
        return wire
    }

    /// Decodes the server's unmasked output frames, allowing RSV1 (a compressed server frame).
    private func serverFrames(_ bytes: [UInt8]) throws -> [WebSocketFrame] {
        let decoder = WebSocketFrameDecoder(permessageDeflate: true)
        return try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            var frames: [WebSocketFrame] = []
            while let frame = try decoder.nextFrame(&reader) { frames.append(frame) }
            return frames
        }
    }
}
