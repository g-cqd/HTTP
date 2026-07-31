//
//  HTTPServer+ChunkedStreaming.swift
//  HTTPServer
//
//  RFC 9112 §7.1 chunked framing for a *streamed* request body — the emitting counterpart of
//  HTTPServer+Chunked's accumulating `frameChunkedBody`. Both resume one ``ChunkedBodyDecoder`` across
//  reads; the difference is what they do with the decoded octets. The buffered path keeps them, because
//  it has to build a `ParsedRequest` out of the whole body. This one hands each pass's octets to the
//  handler and drops them, so nothing decoded is ever retained.
//
//  They are separate drivers rather than a flag on ``HTTPServer/ChunkedProgress`` because they differ in
//  more than accumulation: this one owns a bounded ``RequestBodyWindow`` instead of decoding out of the
//  connection's keep-alive buffer, and it must hand the pipelined remainder back at the end. Trailers
//  need no handling on either path — the decoder validates and discards them (§7.1.2).
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer where C.Duration == Duration {
    /// Streams a chunked body (RFC 9112 §7.1): frames it inside a fixed receive window, offering each
    /// pass's decoded octets to `handoff`, and returns the consumed index — `nil` on truncation or an
    /// over-limit / malformed chunk.
    ///
    /// The body is framed entirely inside the window, so the connection's keep-alive buffer is truncated
    /// to the head up front and the unframed remainder — a pipelined follow-up request — is handed back
    /// to it once the last chunk is seen. The route's `bodyLimit` replaces ``HTTPLimits/maxBodySize``
    /// for the decode when present (Phase 1.2), and the decoder charges it against its own monotonic
    /// count, which is what still bounds a body whose decoded octets are dropped after every pass
    /// (CWE-409).
    func produceChunkedBody(
        _ pending: PendingRequest,
        into handoff: AsyncHandoff,
        buffer: inout [UInt8],
        from connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        bodyLimit: Int?
    ) async -> Int? {
        var window = RequestBodyWindow(
            capacity: limits.effectiveRequestBodyWindow, seeding: buffer[pending.bodyStart...]
        )
        buffer.removeSubrange(pending.bodyStart ..< buffer.count)
        var state = ChunkedBodyDecoder.State()
        let effectiveLimits = limits.bodyLimited(to: bodyLimit)
        while true {
            var chunk: [UInt8] = []
            let step = frame(&window, state: &state, into: &chunk, limits: effectiveLimits)
            if !chunk.isEmpty {
                await handoff.offer(chunk)  // ownership transfer — parks until the handler takes it
            }
            switch step {
                case .success(true):
                    // Whatever the decoder did not frame is a pipelined follow-up: hand it back.
                    buffer.append(contentsOf: window.remainder)
                    return pending.bodyStart
                case .failure:
                    return nil  // an over-limit / malformed chunk after dispatch — close
                case .success(false):
                    guard await replenish(&window, from: connection, deadline: deadline) else {
                        return nil  // truncated mid-chunk
                    }
            }
        }
    }

    /// One decode pass over `window`: appends every newly decoded data octet to `chunk` and advances the
    /// window's framing position.
    ///
    /// `.success(true)` means the terminating zero chunk and trailer section were consumed,
    /// `.success(false)` that more input is needed, `.failure` that the body must be refused.
    private func frame(
        _ window: inout RequestBodyWindow,
        state: inout ChunkedBodyDecoder.State,
        into chunk: inout [UInt8],
        limits: HTTPLimits
    ) -> Result<Bool, HTTP1ParseError> {
        // One allocation sized to what this pass can possibly produce (bounded by the window), instead
        // of the handful a geometric append would make growing into the same size.
        chunk.reserveCapacity(window.unframedCount)
        var position = window.position
        let result: Result<Bool, HTTP1ParseError> = window.bytes.withUnsafeBytes { raw in
            Result { () throws(HTTP1ParseError) in
                var reader = ByteReader(raw, startingAt: position)
                let done = try ChunkedBodyDecoder.advance(
                    &reader, state: &state, into: &chunk, limits: limits
                )
                position = reader.position
                return done
            }
        }
        window.advance(to: position)
        return result
    }

    /// Compacts `window` and reads one bounded chunk of wire octets into it; `false` at EOF.
    ///
    /// The room reported is always positive — the window's floor guarantees the decoder consumes or
    /// fails closed before it can fill (see ``HTTPLimits/effectiveRequestBodyWindow``) — so this never
    /// degenerates into a zero-length read loop.
    private func replenish(
        _ window: inout RequestBodyWindow,
        from connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        let room = window.makeRoom()
        deadline.arm(clock.now.advanced(by: limits.idleTimeout))
        let received = try? await connection.receive(maxLength: room)
        deadline.disarm()
        guard let received, !received.isEmpty else {
            return false
        }
        window.append(received)
        return true
    }
}
