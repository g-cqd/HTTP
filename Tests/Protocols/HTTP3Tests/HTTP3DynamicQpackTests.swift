//
//  HTTP3DynamicQpackTests.swift
//  HTTP3Tests
//
//  RFC 9204 — the QPACK dynamic table wired through the HTTP/3 connection. The server advertises a
//  non-zero `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, applies the peer's encoder-stream inserts into the
//  decoder's dynamic table and acknowledges them with an Insert Count Increment (§4.4.3), then decodes
//  a request whose field section references the dynamic table and acknowledges that section (§4.4.1) —
//  both emitted as role-addressed sends on the server's decoder stream.
//

import HTTPCore
import QPACK
import Testing

@testable import HTTP3

@Suite("RFC 9204 — QPACK dynamic table over the HTTP/3 connection")
struct HTTP3DynamicQpackTests: HTTP3WireFixtures {
    private static let encoderStream = QUICStreamID(6)
    private static let requestStreamID = QUICStreamID(0)
    private static let control = QUICStreamID(2)

    @Test("encoder-stream inserts are acknowledged with an Insert Count Increment (§4.4.3)")
    func insertsAreAcknowledged() throws {
        var connection = HTTP3Connection()
        _ = connection.outbound()  // drain the init actions (stream openers + server SETTINGS)
        _ = try connection.receive(
            Self.encoderStream,
            [0x02] + insertLiteral("custom", "value"),
            fin: false
        )
        // The decoder applied one insert → an Insert Count Increment of 1 on the decoder stream.
        #expect(decoderStreamSend(&connection) == QPACKInstructions.insertCountIncrement(1))
    }

    @Test("a request referencing the dynamic table decodes and is Section-Acknowledged (§4.4.1)")
    func dynamicRequestDecodesAndAcknowledges() throws {
        var connection = HTTP3Connection()
        _ = connection.outbound()
        // Insert `:authority: dyn.example` (name reference to static index 0) into the dynamic table.
        _ = try connection.receive(
            Self.encoderStream,
            [0x02] + insertNameReference(staticIndex: 0, "dyn.example"),
            fin: false
        )
        _ = connection.outbound()  // drain the Insert Count Increment

        // Request prefix RIC=1, Base=1: static :method/:scheme/:path + a dynamic indexed :authority.
        let section: [UInt8] = [0x02, 0x00, 0xD1, 0xD7, 0xC1, 0x80]
        let events = try connection.receive(Self.requestStreamID, requestStream(section), fin: true)
        guard case .request(_, let request, _) = events.first else {
            Issue.record("expected a request event")
            return
        }
        #expect(request.method == .get)
        #expect(request.authority == "dyn.example")  // resolved from the dynamic table
        #expect(
            decoderStreamSend(&connection)
                == QPACKInstructions.sectionAcknowledgment(streamID: Self.requestStreamID.rawValue))
    }

    @Test("a request blocked on a not-yet-received insert is buffered, then unblocked (§2.1.2)")
    func blockedRequestUnblocksOnInsert() throws {
        var connection = HTTP3Connection()
        _ = connection.outbound()

        // The request indexes a dynamic :authority (RIC=1) before the insert arrives — it must buffer,
        // surfacing no request and acknowledging nothing yet.
        let section: [UInt8] = [0x02, 0x00, 0xD1, 0xD7, 0xC1, 0x80]
        let blocked = try connection.receive(
            Self.requestStreamID, requestStream(section), fin: true
        )
        #expect(blocked.isEmpty)
        #expect(decoderStreamSends(&connection).isEmpty)

        // The encoder delivers `:authority: dyn.example`; the buffered request now decodes and surfaces
        // from the *encoder* stream's receive (RFC 9204 §2.1.2).
        let events = try connection.receive(
            Self.encoderStream,
            [0x02] + insertNameReference(staticIndex: 0, "dyn.example"),
            fin: false
        )
        guard case .request(_, let request, _) = events.first else {
            Issue.record("expected the unblocked request event")
            return
        }
        #expect(request.authority == "dyn.example")
        // The decoder stream now carries both the Insert Count Increment and the Section Acknowledgment.
        let sends = decoderStreamSends(&connection)
        let ack = QPACKInstructions.sectionAcknowledgment(streamID: Self.requestStreamID.rawValue)
        #expect(sends.contains(QPACKInstructions.insertCountIncrement(1)))
        #expect(sends.contains(ack))
    }

    @Test("more blocked streams than the limit is QPACK_DECOMPRESSION_FAILED (§2.1.2)")
    func blockedStreamLimitEnforced() {
        var connection = HTTP3Connection()
        _ = connection.outbound()
        // 17 request streams each blocked on RIC=4 (the §4.5.1 prefix [0x05, 0x00]) — one past the
        // advertised 16-stream limit, so the last is a connection error.
        for raw in stride(from: UInt64(0), through: 64, by: 4) {
            _ = try? connection.receive(QUICStreamID(raw), requestStream([0x05, 0x00]), fin: false)
        }
        #expect(
            closeConnectionCode(&connection)
                == UInt64(QPACKError.Code.decompressionFailed.rawValue))
    }

    @Test("the response encoder uses the dynamic table once the peer advertises capacity (§4.3)")
    func responseEncoderInsertsOnRepeatedHeader() throws {
        var connection = HTTP3Connection()
        _ = connection.outbound()
        // The peer advertises a QPACK dynamic-table capacity → our response encoder enables.
        _ = try connection.receive(Self.control, controlPreamble([(0x01, 4_096)]), fin: false)

        var fields = HTTPFields()
        fields.append("Frobnicator/9.9", for: .server)  // a value the static table does not hold
        let response = HTTPResponse(status: .ok, headerFields: fields)

        let setCapacity = QPACKInstructions.setDynamicTableCapacity(4_096)
        // First response → only the one-time Set Capacity (insert-on-second-use defers the insert).
        try answer(&connection, on: QUICStreamID(0), response)
        #expect(encoderStreamSends(&connection) == [setCapacity])

        // Second response with the same header → the encoder inserts it on its QPACK encoder stream.
        try answer(&connection, on: QUICStreamID(4), response)
        let sends = encoderStreamSends(&connection)
        #expect(sends.count == 1)
        #expect(sends.first != setCapacity)
    }

    // MARK: Helpers

    /// Feeds a minimal request on `stream`, then answers it with `response` (no body).
    private func answer(
        _ connection: inout HTTP3Connection, on stream: QUICStreamID, _ response: HTTPResponse
    ) throws {
        _ = try connection.receive(stream, requestStream(requestFieldSection()), fin: true)
        try connection.respond(to: stream, response, body: [])
    }

    /// Every role-addressed send queued on the QPACK encoder stream, drained in order.
    private func encoderStreamSends(_ connection: inout HTTP3Connection) -> [[UInt8]] {
        var sends: [[UInt8]] = []
        for action in connection.outbound() {
            if case .send(.role(.qpackEncoder), let bytes, _) = action {
                sends.append(bytes)
            }
        }
        return sends
    }

    /// The bytes of the first role-addressed send on the QPACK decoder stream, if any.
    private func decoderStreamSend(_ connection: inout HTTP3Connection) -> [UInt8]? {
        for action in connection.outbound() {
            if case .send(.role(.qpackDecoder), let bytes, _) = action {
                return bytes
            }
        }
        return nil
    }

    /// Every role-addressed send queued on the QPACK decoder stream, drained in order.
    private func decoderStreamSends(_ connection: inout HTTP3Connection) -> [[UInt8]] {
        var sends: [[UInt8]] = []
        for action in connection.outbound() {
            if case .send(.role(.qpackDecoder), let bytes, _) = action {
                sends.append(bytes)
            }
        }
        return sends
    }

    private func insertLiteral(_ name: String, _ value: String) -> [UInt8] {
        var out: [UInt8] = []
        QPACKString.encode(Array(name.utf8), prefixBits: 5, firstByte: 0x40, into: &out)  // 01
        QPACKString.encode(Array(value.utf8), prefixBits: 7, into: &out)
        return out
    }

    private func insertNameReference(staticIndex: Int, _ value: String) -> [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(staticIndex, prefixBits: 6, firstByte: 0xC0, into: &out)  // 1 T=1
        QPACKString.encode(Array(value.utf8), prefixBits: 7, into: &out)
        return out
    }
}
