//
//  HTTPServer+HTTP3Dispatch.swift
//  HTTPServer
//
//  The per-connection HTTP/3 output dispatcher (audit addendum P0.3). Every inbound QUIC stream is
//  read on its own task, but they all feed ONE connection-scoped engine, and the engine's output is
//  addressed by stream id — it is not a reply to the caller's stream. RFC 9204 §2.1.2 makes that the
//  normal case: encoder-stream inserts unblock a field section belonging to a *request* stream, so
//  feeding the encoder stream returns a `request` event and `send` actions for the request stream.
//
//  Before this file, `applyHTTP3` matched actions against the calling task's own `stream` and dropped
//  everything else in its `default` case, and the request was answered on the calling task's stream —
//  so a blocked request's response was written nowhere at all. Here the engine's single-owner
//  discipline is unchanged (the actor still owns the state machine); this dispatcher owns only the
//  *routing* of its output, through ``HTTP3StreamRegistry``.
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport
internal import WebSocket

extension HTTPServer {
    /// Performs the engine's outbound actions, each on the stream its id names (RFC 9114 §6.1).
    ///
    /// A `send`/`resetStream` for a stream that is no longer registered is dropped — the stream was
    /// already reset or retired, and QUIC has no way to deliver on it.
    func applyHTTP3(
        _ actions: [HTTP3Connection.Action],
        in scope: HTTP3ConnectionScope
    ) async {
        for action in actions {
            switch action {
                case .send(.id(let id), let bytes, let fin):
                    try? await scope.registry.writer(for: id)?.send(bytes, fin: fin)
                case .send(.role(let role), let bytes, let fin):
                    // QPACK Insert Count Increment / Section Acknowledgment on our decoder stream (§4.4).
                    await scope.engine.sendOnRole(role, bytes, fin: fin)
                case .resetStream(let id, let code):
                    // Through the funnel like every other abandonment (R5-P0c): the engine dropped its
                    // own record when it queued this, but the deadline and the registry entry are the
                    // driver's, and they were being left armed and registered.
                    await retireHTTP3Stream(id, errorCode: code, in: scope)
                case .closeConnection(let code):
                    await scope.quic.close(errorCode: code)
                case .openUniStream:
                    break  // the server's own streams are opened once, at connection start (§6.2)
            }
        }
    }

    /// Feeds one stream's octets to the engine and performs everything the engine asked for.
    ///
    /// The single seam every read path shares (R5-P0b): the engine files each foreign event against the
    /// stream it names *inside its own isolation*, so the caller can never hold a batch across a
    /// suspension point while another task decides that stream no longer needs an entry. What comes
    /// back is only what belongs to the caller, plus the streams whose mailbox refused their batch and
    /// must therefore be retired (RFC 9114 §8.1 H3_EXCESSIVE_LOAD, CWE-770).
    func receiveHTTP3(
        _ id: QUICStreamID,
        _ bytes: [UInt8],
        fin: Bool,
        in scope: HTTP3ConnectionScope
    ) async -> [HTTP3Connection.Event] {
        let reception = await scope.engine.receive(
            id, bytes, fin: fin, routingInto: scope.registry
        )
        await applyHTTP3(reception.actions, in: scope)
        for overflowed in reception.overflowed {
            // A peer growing an unbounded routed queue is refused, not buffered (CWE-770) — and
            // refused through the funnel, so its engine record goes with the wire reset.
            await retireHTTP3Stream(
                overflowed,
                errorCode: HTTP3ErrorCode.h3ExcessiveLoad.rawValue,
                in: scope
            )
        }
        return reception.own
    }

    /// Ends the driving phase for `id`, now that the task reading it has stopped.
    ///
    /// Decides whether anything is still owed on the stream, and keeps its registry entry if so.
    ///
    /// Delegated whole to the engine actor rather than assembled here out of an `isBlocked` read and a
    /// registry call. Those were two isolation hops with a gap between them, and the gap is exactly
    /// where a QPACK unblock lands: the engine cleared the blocked state, this read said "nothing
    /// owed", the entry was dropped, and the routed request then arrived for a stream the registry no
    /// longer knew (RFC 9204 §2.1.2).
    ///
    /// - Returns: whether the entry was kept, for the connection dispatcher to answer on.
    @discardableResult
    func concludeHTTP3Driving(
        _ id: QUICStreamID,
        registry: HTTP3StreamRegistry,
        engine: Engine
    ) async -> Bool {
        await engine.endDriving(id, registry: registry)
    }

    /// Drains the connection's dispatcher ticket channel, serving each named stream's mailbox.
    ///
    /// One long-lived task per connection, running the streams concurrently in a discarding group so a
    /// slow handler on one unblocked stream cannot stall another's.
    ///
    /// The channel carries stream ids only (audit REG-1). The events themselves stay in the registry's
    /// bounded mailbox, and a stream is ticketed only on its no-ticket → ticket transition, so at most
    /// one ticket per registered stream is ever outstanding — an `.unbounded` policy that is *provably*
    /// bounded, rather than a fixed buffer with a drop policy.
    func drainRoutedHTTP3(
        _ tickets: AsyncStream<QUICStreamID>,
        in scope: HTTP3ConnectionScope
    ) async {
        await withDiscardingTaskGroup { group in
            for await id in tickets {
                group.addTask { await self.serveRoutedHTTP3(id, in: scope) }
            }
        }
    }

    /// Serves the mailbox of one ticketed stream, whose own task has ended.
    private func serveRoutedHTTP3(_ id: QUICStreamID, in scope: HTTP3ConnectionScope) async {
        // Both may be gone by now — the stream can be retired between the ticket and this task running,
        // in which case there is nothing left to write on and nothing left to write.
        guard let stream = scope.registry.writer(for: id) else {
            return
        }
        let events = scope.registry.takeMailbox(id)
        guard !events.isEmpty else {
            return
        }
        // This dispatcher is now the stream's only driver, so it drives it inside the same retirement
        // scope the stream's own task used (R5-P0c).
        await withHTTP3RequestStream(id, in: scope) {
            await self.serveOrphanedHTTP3(events, on: stream, in: scope)
        }
    }

    /// Serves a routed batch whose stream is no longer being read — its FIN or EOF already arrived, so
    /// this dispatcher is the only writer left for it.
    private func serveOrphanedHTTP3(
        _ events: [HTTP3Connection.Event],
        on stream: any QUICStream,
        in scope: HTTP3ConnectionScope
    ) async -> HTTP3StreamExit {
        for (index, event) in events.enumerated() {
            switch event {
                case .request(let id, let request, let body):
                    await answerHTTP3Request(
                        id,
                        request: request,
                        body: body,
                        stream: stream,
                        in: scope
                    )
                    return .answered
                case .requestHead(let id, let request):
                    guard scope.registry.claim(id) != nil else {
                        return .answered  // another driver has it; this scope owes nothing
                    }
                    // The stream's own task is gone, so this dispatcher owns its reads too: give the
                    // feed loop the same inbox shape the serve loop uses (audit REG-2), fed by a
                    // reader task of ours rather than by a `receive()` call inline in the loop.
                    let inbox = HTTP3StreamInbox()
                    let reader = Task { await Self.pumpHTTP3Inbound(stream, into: inbox) }
                    defer {
                        reader.cancel()
                        inbox.close()
                    }
                    return await serveHTTP3StreamingRequest(
                        id,
                        request: request,
                        buffered: Self.trailingBody(of: events, after: index),
                        stream: stream,
                        inbox: inbox,
                        in: scope
                    )
                case .extendedConnect, .tunnelData, .tunnelClosed:
                    // A tunnel needs a live reader to pump it; its stream has none (RFC 9220).
                    return .abandoned(errorCode: HTTP3ErrorCode.h3RequestRejected.rawValue)
                case .requestBodyChunk, .requestEnd, .goAway:
                    break  // consumed by the streaming path above / connection-scoped
            }
        }
        // The batch held nothing this dispatcher can act on — leftover body chunks for a stream whose
        // driver is already gone — and no other driver exists once a stream is ticketed here, so the
        // request will never be completed (RFC 9114 §8.1).
        return .abandoned(errorCode: HTTP3ErrorCode.h3RequestIncomplete.rawValue)
    }
}
