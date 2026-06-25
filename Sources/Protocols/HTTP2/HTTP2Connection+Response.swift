//
//  HTTP2Connection+Response.swift
//  HTTP2
//
//  RFC 9113 §8.3.2 — the server-response half of the connection engine: encoding an HTTPResponse into
//  a HEADERS frame (`:status` first, then the fields) and releasing its body through the send-side
//  flow controller. Kept in its own file so HTTP2Connection.swift stays focused on inbound state.
//

internal import HPACK
public import HTTPCore

extension HTTP2Connection {
    /// Queues a response on `streamID`: a HEADERS frame and, if present, DATA frames (RFC 9113 §8.3.2).
    ///
    /// The header block is HPACK-encoded with `:status` first; the body is split into DATA frames no
    /// larger than the peer's SETTINGS_MAX_FRAME_SIZE, with END_STREAM on the final frame. The stream
    /// is advanced through its §5.1 state machine and dropped once closed.
    public mutating func respond(
        to streamID: HTTP2StreamID,
        _ response: HTTPResponse,
        body: [UInt8] = []
    ) throws(HTTP2Error) {
        guard var record = streams.removeValue(forKey: streamID) else {
            throw .connection(.internalError, "response for an unknown stream")
        }
        let hasBody = !body.isEmpty
        // Advance the state machine before touching the encoder, so a bad state never desyncs HPACK.
        try record.stream.sendHeaders(endStream: !hasBody)
        let block = encodeResponseSection(response)
        var headerFlags: HTTP2FrameFlags = [.endHeaders]
        if !hasBody { headerFlags.insert(.endStream) }
        writer.writeFrame(.headers, flags: headerFlags, streamID: streamID, payload: block)
        if hasBody {
            // The body is logically sent now (END_STREAM); its octets are released as the connection
            // and stream send windows allow (RFC 9113 §6.9), the remainder awaiting a WINDOW_UPDATE.
            try record.stream.sendData(endStream: true)
            record.pending = body
            record.pendingEndStream = true
        }
        flushStream(streamID, &record)
    }

    /// Encodes the response field section as an HPACK header block, `:status` first (RFC 9113 §8.3.2).
    ///
    /// Writes straight into a reserved buffer — no intermediate `[HPACKField]` array, no buffer
    /// regrowth, no per-response status itoa. Names use the canonical (lower-cased) form: HTTP/2 field
    /// names MUST be lowercase (§8.2.1), it is stored (so no per-field `rawName` materialization), and it
    /// is the same spelling for the registered names a response uses. Internal so an allocation test can
    /// measure it.
    mutating func encodeResponseSection(_ response: HTTPResponse) -> [UInt8] {
        var output: [UInt8] = []
        output.reserveCapacity(512)
        encoder.encode(
            HPACKField(name: ":status", value: response.status.decimalString), into: &output
        )
        for field in response.headerFields {
            encoder.encode(
                HPACKField(name: field.name.canonicalName, value: field.value), into: &output
            )
        }
        return output
    }
}
