//
//  H3Gate.swift
//  HTTPServerTests
//
//  A wired ``HTTPServer/HTTP3ConnectionScope`` for tests that drive one HTTP/3 stream's decisions
//  directly rather than through a whole connection serve loop.
//
//  Same lesson as ``H2Gate`` (audit R5-SEC1b): `serveHTTP3` builds the ``HTTP3StreamRegistry`` FIRST and
//  closes the engine's `resolveRoute` over it, so every field section that decodes files a
//  ``DispatchPlan`` against its stream. A scope assembled from a fresh registry and an engine whose
//  `resolveRoute` returns `.unmatched` cannot exist in production — every plan lookup misses — and a
//  test written against that shape cannot observe which responder generation a stream belongs to. This
//  builds the pair together so the two halves cannot drift apart.
//

import HTTP3
import HTTPCore
import HTTPTransport

@testable import HTTPServer

/// Sans-I/O scaffolding for the HTTP/3 per-stream driver tests.
enum H3Gate {
    /// A connection scope wired exactly as ``HTTPServer/serveHTTP3(_:)`` wires one.
    ///
    /// The registry's mailbox budget, the engine's limits and the responder generation all come from
    /// `server`, and `resolveRoute` reads ``HTTPServer/currentSnapshot`` per head and files the
    /// resulting plan — so a reload staged between a head and its dispatch is observed here exactly as
    /// the serve loop observes it.
    ///
    /// `connectProtocol` advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220), without which the
    /// engine rejects an Extended CONNECT instead of surfacing it.
    static func scope<C: Clock>(
        for server: HTTPServer<C>,
        quic: FakeQUICConnection,
        connectProtocol: Bool = false
    ) -> HTTPServer<C>.HTTP3ConnectionScope where C.Duration == Duration {
        let registry = HTTP3StreamRegistry(mailboxByteBudget: server.limits.maxBodySize)
        let resolveRoute: @Sendable (QUICStreamID, HTTPRequest) -> RequestBodyPolicy = {
            id, request in
            let snapshot = server.currentSnapshot
            let plan = DispatchPlan(
                snapshot: snapshot,
                match: snapshot.resolver?
                    .match(method: request.method, path: request.path, isUpgrade: false)
            )
            registry.file(plan, for: id)
            return RequestBodyPolicy(limit: plan.bodyLimit, isStreaming: plan.streamsBody)
        }
        return HTTPServer<C>
            .HTTP3ConnectionScope(
                quic: quic,
                registry: registry,
                engine: HTTPServer<C>
                    .Engine(
                        limits: server.limits,
                        enableConnectProtocol: connectProtocol,
                        resolveRoute: resolveRoute
                    ),
                deadlines: HTTP3StreamDeadlines<C.Instant>()
            )
    }
}
