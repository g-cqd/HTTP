//
//  HTTPServer+HTTP2Streaming.swift
//  HTTPServer
//
//  Native HTTP/2 response streaming (P6b / RFC 9113 §8.1), layered on the engine's incremental DATA API
//  (`respondHeaders` / `sendBodyChunk` / `endStream` / `pendingBacklog`). The merged-mailbox consumer
//  (HTTPServer+HTTP2.swift) cannot run a producer inline — a producer blocking the consumer could not
//  process the WINDOW_UPDATE that reopens an exhausted send window (§6.9), deadlocking — so each
//  streaming response's body producer runs behind a dedicated relay task that only ever touches a
//  Sendable one-slot ``AsyncHandoff`` (1-chunk backpressure) and an ``HTTP2StreamPermit``. The relay
//  reports every pulled item back to the consumer as a `.streamChunk` wakeup rather than touching the
//  engine itself, which stays single-owner on the consumer throughout (HPACK / flow control / frame-order
//  correctness — the one invariant that must never break).
//
//  Multiple relays — one per concurrently-streaming response — progress independently: each has its own
//  `AsyncHandoff`, its own `HTTP2StreamPermit`, and its own local ``IdleDeadline`` (FIX #1 parity: a
//  wedged producer is reaped, a progressing one is not); the consumer just applies whichever
//  `.streamChunk` / `.requestReady` / `.inbound` wakeup arrives next, in whatever order, so one streaming
//  response is never blocked to completion by another (or by a buffered request, or a tunnel).
//
//  Memory bound: a relay pulls its NEXT chunk only once the consumer has granted permission — which it
//  does only after discovering (via `engine.pendingBacklog(of:)`, readable only on the consumer) that
//  this stream's backlog has drained to zero — so at most one chunk is ever queued in the engine beyond
//  what the send window currently allows, exactly the bound the original single-stream design relied on.
//

internal import HTTP2
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Applies a request's finished response to `streamID`: buffered directly, or — for a `.stream` body
    /// — HEADERS now plus a dedicated relay task pumping its DATA (P6b / RFC 9113 §8.1), so multiple
    /// native-streaming responses progress concurrently. Returns true on a connection-fatal fault; the
    /// caller flushes whatever the engine queued (best-effort GOAWAY) and closes either way.
    func beginHTTP2Response(
        streamID: HTTP2StreamID,
        response: ServerResponse,
        engine: inout HTTP2Connection,
        group: inout DiscardingTaskGroup,
        relays: inout [HTTP2StreamID: HTTP2StreamPermit],
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) -> Bool {
        guard let bodyStream = response.stream else {
            do {
                try engine.respond(to: streamID, withAltSvc(response.head), body: response.body)
                return false
            }
            catch {
                // A stream-level fault is contained — other streams keep being served; a connection-level
                // fault is fatal (matches the buffered path's original convention).
                return error.isConnectionError
            }
        }
        do {
            try engine.respondHeaders(to: streamID, withAltSvc(response.head))
        }
        catch {
            return true  // responding to an unknown stream is an internal error — close (matches today)
        }
        let handoff = AsyncHandoff()
        let permit = HTTP2StreamPermit()
        relays[streamID] = permit
        group.addTask { [self] in
            let producer = Task { [handoff] in
                do {
                    try await bodyStream.produce(H2StreamWriter(handoff: handoff))
                    await handoff.finish()
                }
                catch {
                    await handoff.fail()
                }
            }
            await runHTTP2StreamRelay(streamID: streamID, handoff: handoff, permit: permit, into: continuation)
            producer.cancel()
            // Unblock a producer still parked on an offer (a no-op once it has ended).
            await handoff.fail()
        }
        return false
    }

    /// Pumps one native-streaming response's body: waits for the consumer's pull permission, pulls the
    /// producer's next item through the one-slot handoff, and reports it back — never touching `engine`
    /// itself (only the consumer may; see ``HTTP2StreamPermit``'s file comment).
    ///
    /// A dedicated local ``IdleDeadline`` + watchdog reaps a producer that wedges — never offers a chunk
    /// within `idleTimeout` — independent of the whole-connection deadline (FIX #1 parity for a single
    /// relay). The watchdog is bound via `async let`, so it is automatically cancelled and awaited the
    /// moment this function returns, however it returns — no lingering napping task outlives its relay.
    ///
    /// Escalation scope: like every local watchdog in this design, a lapse here reports
    /// `.localDeadlineLapsed`, which the consumer treats as connection-fatal (mirroring v1's existing
    /// "a wedged producer takes the connection down" behavior, now just reached from one of possibly
    /// several concurrent relays instead of the sole stream that could exist before) rather than
    /// surgically resetting only this one stream — resetting just this stream would need the relay to
    /// mutate `engine` itself, which is exactly what it must never do.
    private func runHTTP2StreamRelay(
        streamID: HTTP2StreamID,
        handoff: AsyncHandoff,
        permit: HTTP2StreamPermit,
        into continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async {
        let localDeadline = IdleDeadline<C.Instant>()
        // Auto-cancelled and awaited the moment this function returns (an un-named `async let` binding
        // is still a fully structured child task) — however it returns, so a finished relay never leaves
        // a lingering napping watchdog task for the rest of the connection's life.
        async let _: Void = runLocalIdleWatchdog(localDeadline) {
            continuation.yield(.localDeadlineLapsed)
        }
        while true {
            await permit.waitForGrant()
            localDeadline.arm(clock.now.advanced(by: limits.idleTimeout))
            let item = await handoff.next()
            localDeadline.disarm()
            continuation.yield(.streamChunk(streamID, item))
            guard case .chunk = item else {
                return
            }
        }
    }

    /// Grants pull permission to every relay whose stream backlog has drained to zero.
    ///
    /// Called after any engine mutation that could have freed send-window room for one or more streams —
    /// an inbound WINDOW_UPDATE / SETTINGS change, or the consumer's own flush right after applying a
    /// relay's chunk — since only the consumer may read `engine.pendingBacklog(of:)` (RFC 9113 §6.9); a
    /// relay never reads the engine itself. Cheap to call unconditionally: the relay count is bounded by
    /// how many responses are concurrently streaming, not by request rate.
    func releaseDrainedRelays(
        _ relays: [HTTP2StreamID: HTTP2StreamPermit], engine: inout HTTP2Connection
    ) async {
        for (streamID, permit) in relays where engine.pendingBacklog(of: streamID) == 0 {
            await permit.grant()
        }
    }

    /// Drains the engine's queued outbound octets to the transport; returns true on a transport fault.
    ///
    /// Bounds the flush by `deadline`: a slow-reading peer that fills the socket send buffer is reaped
    /// (a paired watchdog cancels whatever unblocks the parked send — see the caller's own local-deadline
    /// design) instead of pinning the caller forever; each flush re-arms, so a progressing transfer is
    /// not reaped.
    ///
    /// `internal` (not `private`) so the HTTP/2 consumer can flush a completed response — or any other
    /// queued frame — the instant it is ready, not batched behind unrelated work.
    func flushHTTP2(
        _ engine: inout HTTP2Connection,
        to connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>
    ) async -> Bool {
        let outbound = engine.outboundBytes()
        guard !outbound.isEmpty else {
            return false
        }
        deadline.arm(clock.now.advanced(by: limits.idleTimeout))
        defer { deadline.disarm() }
        do {
            try await connection.send(outbound)
            return false
        }
        catch {
            return true
        }
    }

    /// Bridges the push-based ``ResponseStream`` producer to the pull-based relay via the one-slot
    /// handoff — `write` suspends until the relay takes the chunk (the 1-chunk backpressure bound).
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
