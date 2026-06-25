//
//  HTTPServer+HTTP2Streaming.swift
//  HTTPServer
//
//  Native HTTP/2 response streaming (P6b / RFC 9113 §8.1), layered on the engine's incremental DATA API
//  (`respondHeaders` / `sendBodyChunk` / `endStream` / `pendingBacklog`). The multiplexed serve loop
//  cannot run a producer inline — a producer blocking the loop could not read the `WINDOW_UPDATE` that
//  reopens an exhausted send window (§6.9), deadlocking — so the body producer runs in a child task that
//  only touches a Sendable one-slot ``AsyncHandoff`` (1-chunk backpressure). The single serve task owns
//  the engine throughout: it pulls a chunk only when the send window has room (`pendingBacklog == 0`),
//  and while window-blocked it reads inbound so a WINDOW_UPDATE drains the backlog. Memory is bounded to
//  one in-flight chunk and the path is deadlock-free (the loop always reads inbound when blocked).
//
//  v1 limitation: while one stream streams, a sibling stream's request is answered only between this
//  stream's chunks, and buffered rather than itself streamed; a tunnel event is deferred. The buffered
//  fallback remains for every non-streaming response.
//

internal import HTTP2
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// One iteration's outcome for the streaming pump.
    private enum StreamPumpStep {
        case keepStreaming
        case streamDone  // this stream finished or was reset — the connection continues
        case closeConnection  // a fatal transport / connection-level fault
    }

    /// Responds to one request event — streamed when the response carries a body stream, else buffered.
    ///
    /// `withAltSvc` advertises HTTP/3 (RFC 7838) when a QUIC listener runs (RFC 9113 §8.3.2). Returns
    /// true if a connection-level fault means the whole connection must close; a stream-level fault is
    /// contained (the engine queued RST_STREAM, flushed with the next batch).
    func respondToRequest(
        streamID: HTTP2StreamID,
        request: HTTPRequest,
        body: [UInt8],
        engine: inout HTTP2Connection,
        connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        let response = await responder.respond(to: request, body: body)
        if let bodyStream = response.stream {
            return await streamHTTP2Response(
                withAltSvc(response.head),
                body: bodyStream,
                streamID: streamID,
                engine: &engine,
                connection: connection,
                deadline: deadline
            )
        }
        do {
            try engine.respond(to: streamID, withAltSvc(response.head), body: response.body)
            return false
        }
        catch {
            guard error.isConnectionError else {
                return false  // a stream-level fault is contained — other streams keep being served
            }
            let goAway = engine.outboundBytes()  // RFC 9113 §6.8 — flush GOAWAY before closing
            if !goAway.isEmpty { try? await connection.send(goAway) }
            return true
        }
    }

    /// Streams a response natively on `streamID` (RFC 9113 §8.1); returns true if the connection closes.
    ///
    /// Sends HEADERS (no END_STREAM), drives the producer through a one-slot handoff, and pulls chunks
    /// only as the send window allows — see the file comment for the bound / deadlock argument.
    func streamHTTP2Response(
        _ head: HTTPResponse,
        body: ResponseStream,
        streamID: HTTP2StreamID,
        engine: inout HTTP2Connection,
        connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        do {
            try engine.respondHeaders(to: streamID, head)  // HEADERS, stream stays open for DATA
        }
        catch {
            return true  // responding to an unknown stream is an internal error — close
        }
        if await flushHTTP2(&engine, to: connection) {
            return true
        }
        let handoff = AsyncHandoff()
        let producer = Task { [handoff] in
            do {
                try await body.produce(H2StreamWriter(handoff: handoff))
                await handoff.finish()
            }
            catch {
                await handoff.fail()
            }
        }
        let shouldClose = await pumpHTTP2Stream(
            streamID: streamID,
            handoff: handoff,
            engine: &engine,
            connection: connection,
            deadline: deadline
        )
        producer.cancel()
        // Unblock a producer still parked on an offer (a no-op once it has ended).
        await handoff.fail()
        return shouldClose
    }

    /// Pulls body chunks (when the window has room) / drains inbound (when window-blocked) until the
    /// stream completes, is reset, or a fault forces the connection closed.
    private func pumpHTTP2Stream(
        streamID: HTTP2StreamID,
        handoff: AsyncHandoff,
        engine: inout HTTP2Connection,
        connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        while true {
            let step: StreamPumpStep
            if engine.pendingBacklog(of: streamID) > 0 {
                step = await drainInboundWhileBlocked(
                    streamID: streamID,
                    engine: &engine,
                    connection: connection,
                    deadline: deadline
                )
            }
            else {
                step = await sendNextChunk(
                    streamID: streamID,
                    handoff: handoff,
                    engine: &engine,
                    connection: connection
                )
            }
            switch step {
                case .keepStreaming:
                    continue
                case .streamDone:
                    return false
                case .closeConnection:
                    return true
            }
        }
    }

    /// The send window is exhausted: read inbound so a WINDOW_UPDATE can drain the backlog, answering
    /// any concurrent request buffered and stopping if this stream is reset (RFC 9113 §6.9 / §6.4).
    private func drainInboundWhileBlocked(
        streamID: HTTP2StreamID,
        engine: inout HTTP2Connection,
        connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>
    ) async -> StreamPumpStep {
        deadline.arm(clock.now.advanced(by: limits.idleTimeout))
        let chunk = try? await connection.receive(maxLength: 16_384)
        deadline.disarm()
        guard let chunk, !chunk.isEmpty else {
            return .closeConnection  // EOF or idle timeout while the peer owes a WINDOW_UPDATE
        }
        let events: [HTTP2Connection.Event]
        do {
            events = try engine.receive(chunk)
        }
        catch {
            return .closeConnection  // connection-level protocol error (GOAWAY already queued)
        }
        for event in events {
            if case .streamReset(let id, _) = event, id == streamID {
                return .streamDone  // the peer cancelled this stream — stop, connection continues
            }
            await applyConcurrentEvent(event, engine: &engine)
        }
        return await flushHTTP2(&engine, to: connection) ? .closeConnection : .keepStreaming
    }

    /// The send window has room: pull the next chunk (or the terminal item) and release it.
    private func sendNextChunk(
        streamID: HTTP2StreamID,
        handoff: AsyncHandoff,
        engine: inout HTTP2Connection,
        connection: any TransportConnection
    ) async -> StreamPumpStep {
        switch await handoff.next() {
            case .chunk(let bytes):
                do {
                    try engine.sendBodyChunk(to: streamID, bytes)
                }
                catch {
                    return .closeConnection
                }
                return await flushHTTP2(&engine, to: connection) ? .closeConnection : .keepStreaming
            case .finished:
                try? engine.endStream(to: streamID)
                _ = await flushHTTP2(&engine, to: connection)
                return .streamDone
            case .failed:
                // RST_STREAM so the peer sees an incomplete response, not a clean truncation.
                engine.abortResponse(to: streamID)
                _ = await flushHTTP2(&engine, to: connection)
                return .streamDone
        }
    }

    /// Answers a concurrent request that arrives while another stream is streaming — buffered, since v1
    /// streams one response at a time (other event kinds are deferred until streaming ends).
    private func applyConcurrentEvent(
        _ event: HTTP2Connection.Event,
        engine: inout HTTP2Connection
    ) async {
        guard case .request(let id, let request, let body) = event else {
            return
        }
        let response = await responder.respond(to: request, body: body)
        let buffered = await bufferedResponse(response)
        try? engine.respond(to: id, withAltSvc(buffered.head), body: buffered.body)
    }

    /// Drains the engine's queued outbound octets to the transport; returns true on a transport fault.
    private func flushHTTP2(
        _ engine: inout HTTP2Connection,
        to connection: any TransportConnection
    ) async -> Bool {
        let outbound = engine.outboundBytes()
        guard !outbound.isEmpty else {
            return false
        }
        do {
            try await connection.send(outbound)
            return false
        }
        catch {
            return true
        }
    }

    /// Bridges the push-based ``ResponseStream`` producer to the pull-based serve loop via the one-slot
    /// handoff — `write` suspends until the loop takes the chunk (the 1-chunk backpressure bound).
    private struct H2StreamWriter: ResponseBodyWriter {
        let handoff: AsyncHandoff

        func write(_ chunk: [UInt8]) async throws {
            try Task.checkCancellation()  // stop promptly if the connection closed mid-stream
            guard !chunk.isEmpty else {
                return
            }
            await handoff.offer(chunk)
        }
    }
}
