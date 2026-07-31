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
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        for action in actions {
            switch action {
                case .send(.id(let id), let bytes, let fin):
                    try? await registry.writer(for: id)?.send(bytes, fin: fin)
                case .send(.role(let role), let bytes, let fin):
                    // QPACK Insert Count Increment / Section Acknowledgment on our decoder stream (§4.4).
                    await engine.sendOnRole(role, bytes, fin: fin)
                case .resetStream(let id, let code):
                    registry.writer(for: id)?.reset(errorCode: code)
                    registry.retire(id)
                case .closeConnection(let code):
                    await quic.close(errorCode: code)
                case .openUniStream:
                    break  // the server's own streams are opened once, at connection start (§6.2)
            }
        }
    }

    /// Splits an engine event batch into the events belonging to `owner` and the ones that do not,
    /// depositing the latter in the stream they name; returns the caller's own events.
    ///
    /// Connection-scoped events (GOAWAY, whose id is a *limit*, not a stream) stay with the caller.
    ///
    /// Audit REG-1: a foreign batch goes straight into that stream's bounded mailbox and the outcome is
    /// *inspected*. This used to yield into an `AsyncStream` with `.bufferingOldest(256)` and discard
    /// the result, so past the budget the oldest batches — requests and body chunks — were silently
    /// dropped. There is no lossy hop left: the mailbox either takes the batch, or refuses it and the
    /// stream is reset with H3_EXCESSIVE_LOAD (RFC 9114 §8.1).
    func partitionHTTP3Events(
        _ events: [HTTP3Connection.Event],
        owner: QUICStreamID,
        registry: HTTP3StreamRegistry
    ) -> [HTTP3Connection.Event] {
        var own: [HTTP3Connection.Event] = []
        var foreign: [QUICStreamID: [HTTP3Connection.Event]] = [:]
        var order: [QUICStreamID] = []
        for event in events {
            guard let id = Self.owningStream(of: event), id != owner else {
                own.append(event)
                continue
            }
            if foreign[id] == nil { order.append(id) }
            foreign[id, default: []].append(event)
        }
        for id in order {
            routeHTTP3Events(foreign[id] ?? [], to: id, registry: registry)
        }
        return own
    }

    /// Deposits one foreign batch, escalating a refusal to a stream reset rather than dropping it.
    ///
    /// The deposit cannot park: this runs on a stream task one statement after its own `engine.receive`
    /// returned, so waiting on another stream's application progress would be cross-stream head-of-line
    /// blocking and could deadlock against a peer task depositing back. Failing closed is the
    /// requirement here, exactly as it is for ``BoundedByteChannel/trySend(_:)`` on the HTTP/2 side.
    private func routeHTTP3Events(
        _ events: [HTTP3Connection.Event],
        to id: QUICStreamID,
        registry: HTTP3StreamRegistry
    ) {
        switch registry.deposit(events, for: id) {
            case .queued:
                break  // the owner's inbox, or the dispatcher's ticket, has been signalled
            case .unknown:
                break  // the stream was reset or retired; QUIC has no way to deliver on it
            case .overflow(let stream):
                // A peer growing an unbounded routed queue is refused, not buffered (CWE-770).
                stream.reset(errorCode: HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
                registry.retire(id)
        }
    }

    /// The request stream an event belongs to, or nil when it is connection-scoped (RFC 9114 §5.2 —
    /// GOAWAY carries a stream *limit*, not a stream to act on).
    static func owningStream(of event: HTTP3Connection.Event) -> QUICStreamID? {
        switch event {
            case .request(let id, _, _),
                .requestHead(let id, _),
                .requestBodyChunk(let id, _),
                .requestEnd(let id),
                .extendedConnect(let id, _, _),
                .tunnelData(let id, _),
                .tunnelClosed(let id):
                id
            case .goAway:
                nil
        }
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
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection,
        deadlines: HTTP3StreamDeadlines<C.Instant>
    ) async {
        await withDiscardingTaskGroup { group in
            for await id in tickets {
                group.addTask {
                    await self.serveRoutedHTTP3(
                        id,
                        registry: registry,
                        engine: engine,
                        quic: quic,
                        deadlines: deadlines
                    )
                }
            }
        }
    }

    /// Serves the mailbox of one ticketed stream, whose own task has ended.
    private func serveRoutedHTTP3(
        _ id: QUICStreamID,
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection,
        deadlines: HTTP3StreamDeadlines<C.Instant>
    ) async {
        // Both may be gone by now — the stream can be retired between the ticket and this task running,
        // in which case there is nothing left to write on and nothing left to write.
        guard let stream = registry.writer(for: id) else {
            return
        }
        let events = registry.takeMailbox(id)
        guard !events.isEmpty else {
            return
        }
        await serveOrphanedHTTP3(
            events,
            for: id,
            stream: stream,
            registry: registry,
            engine: engine,
            quic: quic,
            deadlines: deadlines
        )
    }

    /// Serves a routed batch whose stream is no longer being read — its FIN or EOF already arrived, so
    /// this dispatcher is the only writer left for it.
    private func serveOrphanedHTTP3(
        _ events: [HTTP3Connection.Event],
        for streamID: QUICStreamID,
        stream: any QUICStream,
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection,
        deadlines: HTTP3StreamDeadlines<C.Instant>
    ) async {
        for (index, event) in events.enumerated() {
            switch event {
                case .request(let id, let request, let body):
                    await answerHTTP3Request(
                        id,
                        request: request,
                        body: body,
                        stream: stream,
                        engine: engine,
                        quic: quic,
                        registry: registry
                    )
                    return
                case .requestHead(let id, let request):
                    guard registry.claim(id) != nil else {
                        return
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
                    await serveHTTP3StreamingRequest(
                        id,
                        request: request,
                        buffered: Self.trailingBody(of: events, after: index),
                        stream: stream,
                        inbox: inbox,
                        engine: engine,
                        quic: quic,
                        registry: registry,
                        deadlines: deadlines
                    )
                    return
                case .extendedConnect, .tunnelData, .tunnelClosed:
                    // A tunnel needs a live reader to pump it; its stream has none (RFC 9220). Retire
                    // the engine with it (REG-3) — a tunnel record is never dropped by the engine on
                    // its own, so leaving it is a per-refused-tunnel leak.
                    await resetHTTP3Stream(
                        streamID,
                        errorCode: HTTP3ErrorCode.h3RequestRejected.rawValue,
                        registry: registry,
                        engine: engine,
                        quic: quic
                    )
                    return
                case .requestBodyChunk, .requestEnd, .goAway:
                    break  // consumed by the streaming path above / connection-scoped
            }
        }
    }
}
