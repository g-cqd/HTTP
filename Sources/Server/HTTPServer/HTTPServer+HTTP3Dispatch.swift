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
    /// yielding the latter to the connection dispatcher; returns the caller's own events.
    ///
    /// Connection-scoped events (GOAWAY, whose id is a *limit*, not a stream) stay with the caller.
    func partitionHTTP3Events(
        _ events: [HTTP3Connection.Event],
        owner: QUICStreamID,
        routed: AsyncStream<HTTP3RoutedEvents>.Continuation
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
            routed.yield(HTTP3RoutedEvents(streamID: id, events: foreign[id] ?? []))
        }
        return own
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

    /// Drains the connection's routed-event channel, serving each batch on the stream it names.
    ///
    /// One long-lived task per connection, running the batches concurrently in a discarding group so a
    /// slow handler on one unblocked stream cannot stall another's.
    func drainRoutedHTTP3(
        _ routed: AsyncStream<HTTP3RoutedEvents>,
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        await withDiscardingTaskGroup { group in
            for await batch in routed {
                group.addTask {
                    await self.serveRoutedHTTP3(
                        batch, registry: registry, engine: engine, quic: quic
                    )
                }
            }
        }
    }

    /// Serves one routed batch: answer it here when its stream's task has already ended, otherwise
    /// queue it for that task, which holds the tunnel / body-feed state the events need.
    private func serveRoutedHTTP3(
        _ batch: HTTP3RoutedEvents,
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        switch registry.deposit(batch.events, for: batch.streamID) {
            case .queued, .unknown:
                // Queued for the owning task (it drains the mailbox at the top of each read), or the
                // stream is gone — nothing this task may write.
                return
            case .overflow(let stream):
                // A peer growing an unbounded routed queue is refused, not buffered (CWE-770).
                stream.reset(errorCode: HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
                registry.retire(batch.streamID)
            case .orphaned(let stream):
                await serveOrphanedHTTP3(
                    batch, stream: stream, registry: registry, engine: engine, quic: quic
                )
        }
    }

    /// Serves a routed batch whose stream is no longer being read — its FIN or EOF already arrived, so
    /// this dispatcher is the only writer left for it.
    private func serveOrphanedHTTP3(
        _ batch: HTTP3RoutedEvents,
        stream: any QUICStream,
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        for (index, event) in batch.events.enumerated() {
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
                    await serveHTTP3StreamingRequest(
                        id,
                        request: request,
                        buffered: Self.trailingBody(of: batch.events, after: index),
                        stream: stream,
                        engine: engine,
                        quic: quic,
                        registry: registry
                    )
                    return
                case .extendedConnect, .tunnelData, .tunnelClosed:
                    // A tunnel needs a live reader to pump it; its stream has none (RFC 9220).
                    stream.reset(errorCode: HTTP3ErrorCode.h3RequestRejected.rawValue)
                    registry.retire(batch.streamID)
                    return
                case .requestBodyChunk, .requestEnd, .goAway:
                    break  // consumed by the streaming path above / connection-scoped
            }
        }
    }
}
