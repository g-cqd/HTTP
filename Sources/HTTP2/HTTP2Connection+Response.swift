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
        let block = encoder.encode(responseFields(response))
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

    /// The HPACK fields for `response`: the `:status` pseudo-header first, then the regular fields.
    private func responseFields(_ response: HTTPResponse) -> [HPACKField] {
        var fields = [HPACKField(name: ":status", value: String(response.status.code))]
        for field in response.headerFields {
            fields.append(HPACKField(name: field.name.rawName, value: field.value))
        }
        return fields
    }
}
