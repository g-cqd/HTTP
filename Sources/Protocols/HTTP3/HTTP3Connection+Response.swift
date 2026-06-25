//
//  HTTP3Connection+Response.swift
//  HTTP3
//
//  RFC 9114 §4.1 — the server-response half of the connection engine: encoding an HTTPResponse into a
//  QPACK HEADERS frame (the `:status` pseudo-header first, then the lowercased fields) and, if present,
//  a DATA frame, then ending the request stream with FIN. The field section is self-contained (QPACK
//  dynamic table disabled, Required Insert Count 0), so no encoder-stream traffic is generated.
//

public import HTTPCore
internal import QPACK

extension HTTP3Connection {
    /// Queues a response on `streamID`: a QPACK HEADERS frame, an optional DATA frame, and FIN
    /// (RFC 9114 §4.1).
    ///
    /// The header block is QPACK-encoded with `:status` first; the stream is closed with FIN since this
    /// v1 sends the whole response at once. Throws H3_INTERNAL_ERROR if the stream is unknown.
    public mutating func respond(
        to streamID: QUICStreamID,
        _ response: HTTPResponse,
        body: [UInt8] = []
    ) throws(HTTP3Error) {
        guard streams.removeValue(forKey: streamID) != nil else {
            throw .connection(.h3InternalError, "response for an unknown stream")
        }
        let headerBlock = encodeBufferedResponse(response)
        var bytes = HTTP3FrameWriter.frame(.headers, payload: headerBlock)
        if !body.isEmpty {
            HTTP3FrameWriter.append(.data, payload: body, to: &bytes)
        }
        actions.append(.send(stream: .id(streamID), bytes: bytes, fin: true))
    }

    /// Encodes a streaming response's QPACK HEADERS frame on `streamID` and removes the stream from
    /// engine tracking — **without** FIN, and without queuing a body (RFC 9114 §4.1).
    ///
    /// The driver sends the returned bytes (with `fin:false` for a body, or `fin:true` for a HEAD
    /// request), then pumps body DATA frames built by ``dataFrame(_:)`` and FINs the stream itself. This
    /// is the native-streaming counterpart to ``respond(to:_:body:)``: the head is framed here, but the
    /// body and end-of-stream are deferred so a `ResponseStream` can drive the wire chunk by chunk.
    /// Because QUIC streams are independent with transport-level backpressure (RFC 9000 §2), the engine
    /// keeps no state for the streamed body — unlike HTTP/2's window-coupled connection. Throws
    /// H3_INTERNAL_ERROR if the stream is unknown.
    public mutating func respondHeaders(
        to streamID: QUICStreamID,
        _ response: HTTPResponse
    ) throws(HTTP3Error) -> [UInt8] {
        guard streams.removeValue(forKey: streamID) != nil else {
            throw .connection(.h3InternalError, "streaming response for an unknown stream")
        }
        return HTTP3FrameWriter.frame(.headers, payload: encodeResponseSection(response))
    }

    /// Wraps `chunk` as an HTTP/3 DATA frame (RFC 9114 §7.2.1) for incremental response streaming.
    ///
    /// Static and pure: a streamed body's DATA needs no connection state — QUIC streams are independent
    /// (RFC 9000 §2) — so the driver frames and sends each chunk directly, off the serializing actor,
    /// with the transport's per-stream flow control as the backpressure point.
    public static func dataFrame(_ chunk: [UInt8]) -> [UInt8] {
        HTTP3FrameWriter.frame(.data, payload: chunk)
    }

    /// Encodes a response's QPACK field section into a reserved buffer (RFC 9114 §4.1).
    ///
    /// `:status` first, then the lowercased fields (§4.2): no intermediate `[HeaderField]` array, no
    /// buffer regrowth, no per-response status itoa. Internal so an allocation test can measure it.
    func encodeResponseSection(_ response: HTTPResponse) -> [UInt8] {
        var output: [UInt8] = []
        // Reserve once up front so the buffer does not realloc as fields append (a typical response
        // header block fits; a larger one grows from here, still far fewer reallocs than from empty).
        output.reserveCapacity(512)
        encoder.beginSection(into: &output)
        // `:status` first (RFC 9114 §4.1); a cached string for the common codes avoids a per-response
        // `String(code)` allocation (the value also serves as the static-table lookup key).
        encoder.encode(
            HeaderField(name: ":status", value: response.status.decimalString),
            into: &output
        )
        for field in response.headerFields {
            encoder.encode(
                HeaderField(name: field.name.canonicalName, value: field.value), into: &output
            )
        }
        return output
    }

    /// Encodes a buffered response's field section, using the dynamic table when the peer enabled it
    /// (RFC 9204 §4.3) and queuing any encoder-stream inserts on our QPACK encoder stream.
    ///
    /// Only the buffered ``respond(to:_:body:)`` path encodes dynamically: its caller drains the queued
    /// actions, so the encoder-stream inserts reach the peer alongside the response. The streaming
    /// ``respondHeaders(to:_:)`` path stays static (its bytes are returned to the driver directly, with no
    /// action drain), and the encoder never references a fresh insert, so deferring them is harmless.
    private mutating func encodeBufferedResponse(_ response: HTTPResponse) -> [UInt8] {
        guard encoder.dynamicTableEnabled else {
            return encodeResponseSection(response)
        }
        let (section, encoderStream) = encoder.encodeSection(responseFields(response))
        if !encoderStream.isEmpty {
            actions.append(.send(stream: .role(.qpackEncoder), bytes: encoderStream, fin: false))
        }
        return section
    }

    /// Materializes a response's field list (`:status` first, then the lowercased fields) for the dynamic
    /// encoder, which needs the whole section before it can size the §4.5.1 prefix.
    private func responseFields(_ response: HTTPResponse) -> [HeaderField] {
        var fields: [HeaderField] = []
        fields.reserveCapacity(response.headerFields.count + 1)
        fields.append(HeaderField(name: ":status", value: response.status.decimalString))
        for field in response.headerFields {
            fields.append(HeaderField(name: field.name.canonicalName, value: field.value))
        }
        return fields
    }
}
