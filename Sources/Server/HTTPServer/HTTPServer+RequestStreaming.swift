//
//  HTTPServer+RequestStreaming.swift
//  HTTPServer
//
//  The HTTP/1.1 streaming-request-body producer (Phase 1.4, RFC 9112 §6/§7): reads the whole body off
//  the wire, yielding each decoded chunk to the handler's ``HTTPRequestBodyStream`` as it arrives. Split
//  out of HTTPServer+RequestReader so the per-exchange reader stays focused. The body is *always* read to
//  completion — even when the handler abandons the stream — so the keep-alive cursor stays exact and a
//  pipelined follow-up request is never desynced (the desync-safety invariant ``serveStreaming`` relies on).
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer where C.Duration == Duration {
    /// Reads the whole request body off the wire, yielding each decoded chunk to `continuation` as it
    /// arrives, and returns the buffer index just past the consumed body — or `nil` if the body could not
    /// be fully read (truncation, or a chunked body that overran the route limit, ``frameChunkedBody``).
    func produceBody(
        _ pending: PendingRequest,
        into continuation: AsyncStream<[UInt8]>.Continuation,
        buffer: inout [UInt8],
        from connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        bodyLimit: Int?
    ) async -> Int? {
        switch pending.head.framing {
            case .none:
                return pending.bodyStart
            case .contentLength(let length):
                return await produceContentLengthBody(
                    length,
                    after: pending.bodyStart,
                    into: continuation,
                    buffer: &buffer,
                    from: connection,
                    deadline: deadline
                )
            case .chunked:
                return await produceChunkedBody(
                    pending,
                    into: continuation,
                    buffer: &buffer,
                    from: connection,
                    deadline: deadline,
                    bodyLimit: bodyLimit
                )
        }
    }

    /// Streams a Content-Length body: yields any already-buffered octets, then reads the remainder up to
    /// `length`, returning the index just past it (RFC 9112 §6.2) — `nil` if the peer truncated it.
    private func produceContentLengthBody(
        _ length: Int,
        after bodyStart: Int,
        into continuation: AsyncStream<[UInt8]>.Continuation,
        buffer: inout [UInt8],
        from connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>
    ) async -> Int? {
        var consumed = min(buffer.count - bodyStart, length)
        if consumed > 0 {
            continuation.yield(Array(buffer[bodyStart ..< bodyStart + consumed]))
        }
        while consumed < length {
            deadline.arm(clock.now.advanced(by: limits.idleTimeout))
            let before = buffer.count
            let received = (try? await connection.receive(into: &buffer, maxLength: 16_384)) ?? 0
            deadline.disarm()
            guard received > 0 else {
                return nil  // truncated before the declared length
            }
            let take = min(received, length - consumed)
            continuation.yield(Array(buffer[before ..< before + take]))
            consumed += take
        }
        return bodyStart + length
    }

    /// Streams a chunked body (RFC 9112 §7.1), yielding each newly-decoded delta and reading until the
    /// terminating zero chunk; returns the consumed index, or `nil` on truncation / an over-limit chunk.
    private func produceChunkedBody(
        _ pending: PendingRequest,
        into continuation: AsyncStream<[UInt8]>.Continuation,
        buffer: inout [UInt8],
        from connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        bodyLimit: Int?
    ) async -> Int? {
        var chunked = ChunkedProgress()
        var yielded = 0
        while true {
            let step = frameChunkedBody(
                buffer,
                head: pending.head,
                start: pending.bodyStart,
                chunked: &chunked,
                bodyLimit: bodyLimit
            )
            if chunked.body.count > yielded {
                continuation.yield(Array(chunked.body[yielded...]))
                yielded = chunked.body.count
            }
            switch step {
                case .complete(_, let consumed):
                    return consumed
                case .failed:
                    return nil  // an over-limit / malformed chunk after dispatch — close
                case .incomplete:
                    deadline.arm(clock.now.advanced(by: limits.idleTimeout))
                    let received =
                        (try? await connection.receive(into: &buffer, maxLength: 16_384)) ?? 0
                    deadline.disarm()
                    guard received > 0 else {
                        return nil  // truncated mid-chunk
                    }
            }
        }
    }
}
