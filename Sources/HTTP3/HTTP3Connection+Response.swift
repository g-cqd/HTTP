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
        let headerBlock = encoder.encode(responseFields(response))
        var bytes = HTTP3FrameWriter.frame(.headers, payload: headerBlock)
        if !body.isEmpty {
            HTTP3FrameWriter.append(.data, payload: body, to: &bytes)
        }
        actions.append(.send(stream: .id(streamID), bytes: bytes, fin: true))
    }

    /// The QPACK fields for `response`: the `:status` pseudo-header first, then the lowercased fields
    /// (HTTP/3 field names MUST be lowercase, RFC 9114 §4.2).
    private func responseFields(_ response: HTTPResponse) -> [HeaderField] {
        var fields = [HeaderField(name: ":status", value: String(response.status.code))]
        for field in response.headerFields {
            fields.append(HeaderField(name: field.name.canonicalName, value: field.value))
        }
        return fields
    }
}
