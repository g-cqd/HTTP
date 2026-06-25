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
        let headerBlock = encodeResponseSection(response)
        var bytes = HTTP3FrameWriter.frame(.headers, payload: headerBlock)
        if !body.isEmpty {
            HTTP3FrameWriter.append(.data, payload: body, to: &bytes)
        }
        actions.append(.send(stream: .id(streamID), bytes: bytes, fin: true))
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
}
