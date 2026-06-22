//
//  HTTPServer+Chunked.swift
//  HTTPServer
//
//  RFC 9112 §7.1 — resumable chunked-body framing for the HTTP/1.1 read loop, extracted from
//  HTTPServer so the decoder state and its driver live together. The decode resumes across reads so
//  each octet is consumed exactly once — no O(n²) re-scan of the accumulated buffer (audit H1-F1) —
//  and the decoded body grows in place inside the `inout` ``ChunkedProgress``, never copied per read.
//

internal import HTTP1
internal import HTTPCore

extension HTTPServer {

    /// The carried state of a resumable chunked-body decode (audit H1-F1).
    ///
    /// Threaded `inout` across the read loop so the decoded `body` grows in place; `consumed` marks how
    /// far into the buffer the decoder has processed.
    struct ChunkedProgress {
        var started = false
        var state = ChunkedBodyDecoder.State()
        var consumed = 0
        var body = [UInt8]()
    }

    /// Frames a chunked body, *resuming* the decoder across reads so each octet is decoded once.
    func frameChunkedBody(
        _ buffer: [UInt8], head: RequestHead, start: Int, chunked: inout ChunkedProgress
    ) -> BodyStep {
        if !chunked.started {
            chunked.started = true
            chunked.consumed = start
        }
        let result: Result<Bool, HTTP1ParseError> = buffer.withUnsafeBytes { raw in
            Result { () throws(HTTP1ParseError) in
                var reader = ByteReader(raw, startingAt: chunked.consumed)
                let done = try ChunkedBodyDecoder.advance(
                    &reader, state: &chunked.state, into: &chunked.body, limits: limits)
                chunked.consumed = reader.position
                return done
            }
        }
        switch result {
        case .success(true):
            let parsed = ParsedRequest(
                request: head.request, body: chunked.body, version: head.version)
            return .complete(parsed, consumed: chunked.consumed)
        case .success(false):
            return .incomplete
        case .failure(let error):
            return .failed(error)
        }
    }
}
