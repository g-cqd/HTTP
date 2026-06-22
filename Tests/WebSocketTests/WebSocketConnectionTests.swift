//
//  WebSocketConnectionTests.swift
//  WebSocketTests
//
//  RFC 6455 §5 / §6 — the server connection engine: message reassembly (§5.4), the Ping→Pong and
//  Close handshakes (§5.5), masking enforcement (§5.1), and the UTF-8 / Close-code validations
//  (§8.1 / §7.4.1) — each driving the correct event and, on a violation, a Close frame.
//

import HTTPCore
import Testing

@testable import WebSocket

@Suite("RFC 6455 §5/§6 — connection engine")
struct WebSocketConnectionTests {

    // MARK: Messages

    @Test("decodes a complete masked text message")
    func decodesTextMessage() throws {
        var connection = WebSocketConnection()
        let events = try connection.receive(clientFrame(.text, Array("hello".utf8)))
        #expect(events == [.message(opcode: .text, payload: Array("hello".utf8))])
    }

    @Test("reassembles a fragmented message (RFC 6455 §5.4)")
    func reassemblesFragments() throws {
        var connection = WebSocketConnection()
        var wire = clientFrame(.text, Array("Hel".utf8), fin: false)
        wire += clientFrame(.continuation, Array("lo!".utf8), fin: true)
        let events = try connection.receive(wire)
        #expect(events == [.message(opcode: .text, payload: Array("Hello!".utf8))])
    }

    // MARK: Control frames

    @Test("answers a Ping with a Pong carrying the same payload (RFC 6455 §5.5.2)")
    func pingIsAnsweredWithPong() throws {
        var connection = WebSocketConnection()
        let events = try connection.receive(clientFrame(.ping, Array("ka".utf8)))
        #expect(events == [.ping(Array("ka".utf8))])
        let reply = try serverFrames(connection.outboundBytes())
        #expect(reply == [WebSocketFrame(opcode: .pong, payload: Array("ka".utf8))])
    }

    @Test("echoes a Close and reports closing (RFC 6455 §5.5.1)")
    func closeIsEchoed() throws {
        var connection = WebSocketConnection()
        let events = try connection.receive(
            clientFrame(.close, [0x03, 0xE8]))  // code 1000
        #expect(events == [.close(code: .normalClosure, reason: [])])
        #expect(connection.isClosing)
        let reply = try serverFrames(connection.outboundBytes())
        #expect(reply.first?.opcode == .close)
    }

    // MARK: Send

    @Test("send(text:) queues an unmasked server frame (RFC 6455 §5.1)")
    func sendQueuesUnmaskedFrame() throws {
        var connection = WebSocketConnection()
        connection.send(text: "hi")
        let frames = try serverFrames(connection.outboundBytes())
        #expect(frames == [WebSocketFrame(opcode: .text, payload: Array("hi".utf8))])
    }

    // MARK: Violations → Close

    @Test("an unmasked client frame is rejected with Close 1002 (RFC 6455 §5.1)")
    func unmaskedFrameRejected() throws {
        var connection = WebSocketConnection()
        var thrown: WebSocketError?
        do { _ = try connection.receive([0x81, 0x02, 0x48, 0x69]) } catch { thrown = error }
        #expect(thrown == .maskingRequired)
        #expect(try closeCode(connection.outboundBytes()) == WebSocketCloseCode.protocolError)
    }

    @Test("a continuation with no open message is a protocol error (§5.4)")
    func unexpectedContinuationRejected() {
        var connection = WebSocketConnection()
        var thrown: WebSocketError?
        do { _ = try connection.receive(clientFrame(.continuation, [0x00])) } catch {
            thrown = error
        }
        #expect(thrown == .unexpectedContinuation)
    }

    @Test("a data frame interleaved into a fragmented message is rejected (§5.4)")
    func interleavedDataRejected() {
        var connection = WebSocketConnection()
        var wire = clientFrame(.text, [0x41], fin: false)  // open a fragment
        wire += clientFrame(.text, [0x42], fin: true)  // new data frame — illegal
        var thrown: WebSocketError?
        do { _ = try connection.receive(wire) } catch { thrown = error }
        #expect(thrown == .interleavedDataFrame)
    }

    @Test("a non-UTF-8 text message is rejected with Close 1007 (RFC 6455 §8.1)")
    func invalidUTF8Rejected() throws {
        var connection = WebSocketConnection()
        var thrown: WebSocketError?
        do { _ = try connection.receive(clientFrame(.text, [0xFF, 0xFE])) } catch { thrown = error }
        #expect(thrown == .invalidTextEncoding)
        #expect(try closeCode(connection.outboundBytes()) == WebSocketCloseCode.invalidPayloadData)
    }

    @Test("a Close with a reserved status code is rejected (RFC 6455 §7.4.1)")
    func invalidCloseCodeRejected() {
        var connection = WebSocketConnection()
        var thrown: WebSocketError?
        // Close code 1005 must not appear on the wire (RFC 6455 §7.4.1).
        do {
            _ = try connection.receive(clientFrame(.close, [0x03, 0xED]))
        } catch {
            thrown = error
        }
        #expect(thrown == .invalidCloseCode)
    }

    // MARK: Fixtures

    /// A masked client frame (RFC 6455 §5.1/§5.3) for payloads up to 125 octets.
    private func clientFrame(
        _ opcode: WebSocketOpcode, _ payload: [UInt8], fin: Bool = true
    )
        -> [UInt8]
    {
        let key: [UInt8] = [0x12, 0x34, 0x56, 0x78]
        var wire: [UInt8] = [(fin ? 0x80 : 0) | opcode.rawValue, 0x80 | UInt8(payload.count)]
        wire += key
        for (index, byte) in payload.enumerated() { wire.append(byte ^ key[index & 0x3]) }
        return wire
    }

    /// Decodes the server's unmasked output frames.
    private func serverFrames(_ bytes: [UInt8]) throws -> [WebSocketFrame] {
        let decoder = WebSocketFrameDecoder()
        return try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            var frames = [WebSocketFrame]()
            while let frame = try decoder.nextFrame(&reader) { frames.append(frame) }
            return frames
        }
    }

    /// The status code of the first Close frame on the wire.
    private func closeCode(_ bytes: [UInt8]) throws -> WebSocketCloseCode? {
        guard let close = try serverFrames(bytes).first(where: { $0.opcode == .close }),
            close.payload.count >= 2
        else { return nil }
        return WebSocketCloseCode(
            rawValue: UInt16(close.payload[0]) << 8 | UInt16(close.payload[1]))
    }
}
