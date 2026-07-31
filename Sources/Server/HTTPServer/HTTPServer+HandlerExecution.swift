//
//  HTTPServer+HandlerExecution.swift
//  HTTPServer
//
//  The one seam every protocol engine dispatches an application handler through (audit CR-F7).
//
//  There are six `respond` call sites across the three engines — HTTP/1.1 buffered and streaming,
//  HTTP/2 buffered and streaming-route, HTTP/3 buffered and streaming — and before this file each
//  called `responder.respond` directly, inheriting whatever executor its connection's serve task was
//  pinned to. Routing them all through here is what makes ``HandlerExecutionPolicy`` a single
//  decision rather than six.
//
//  What must NOT move is everything else. The scope of the hop is exactly one call:
//
//    * HTTP/1.1's parse state (`buffer`, `start`, `responseBuffer`) stays `inout` locals of the
//      reactor-pinned keep-alive loop and is never captured by the hopped closure — the hop takes
//      owned values (`HTTPRequest`, `RequestBody`, `RequestContext`) and returns one owned value.
//    * HTTP/2's engine, HPACK tables and `connection.send` stay with the single mailbox consumer; a
//      dispatched handler already reports back through the `.requestReady(streamID, response)`
//      wakeup, so the return-to-owner mechanism for ordered writes predates this change and is
//      untouched by it.
//    * HTTP/3's engine is an actor and its writes go to independent QUIC streams (RFC 9000 §2), so
//      per-stream order is the task's own statement order and cross-stream order is not a wire
//      requirement at all. The `sendHTTP3Response` that follows the seam runs after the scoped
//      preference is restored, i.e. back on the reactor, exactly as before.
//
//  No lock is added anywhere: the hop transfers ownership of values across a suspension point, which
//  is what `Sendable` already guarantees, and adds no shared mutable state.
//

internal import HTTPCore

extension HTTPServer {
    /// Runs the responder carried by `plan` under the configured handler execution policy.
    ///
    /// The single dispatch seam for every protocol. Under ``HandlerExecutionPolicy/inline`` this is
    /// the direct call the engines made before the policy existed — one extra enum test, no hop, no
    /// allocation, no shared state — so `.inline` really is a behavioural *and* structural no-op.
    func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        following plan: DispatchPlan
    ) async -> ServerResponse {
        let responder = plan.snapshot.responder
        switch handlerExecution {
            case .inline:
                return await responder.respond(to: request, body: body, context: context)
            case .concurrent:
                return await Self.hopped(responder, request, body, context)
            case .adaptive:
                return await adaptively(responder, request, body, context, following: plan)
        }
    }

    /// Runs the handler where this route's measured service time says it belongs, and files the
    /// result of that run against the route.
    ///
    /// The two timestamps bracket the handler and nothing else, so the measurement is handler time
    /// rather than reactor time — a route is judged on what it costs, not on what the connection
    /// around it was doing. Both are plain monotonic reads; the gate's lock is taken twice per
    /// request on this opt-in path and never across the `await`.
    private func adaptively(
        _ responder: any HTTPResponder,
        _ request: HTTPRequest,
        _ body: RequestBody,
        _ context: RequestContext,
        following plan: DispatchPlan
    ) async -> ServerResponse {
        guard let handlerGate else {
            return await responder.respond(to: request, body: body, context: context)
        }
        let key = RouteExecutionKey(plan.match) ?? .unrouted
        let hops = handlerGate.hops(key)
        let started = handlerGate.timestamp()
        let response =
            hops
            ? await Self.hopped(responder, request, body, context)
            : await responder.respond(to: request, body: body, context: context)
        handlerGate.record(handlerGate.timestamp() - started, for: key)
        return response
    }

    /// Runs `responder` on the global concurrent executor, restoring the caller's preference on exit.
    ///
    /// `globalConcurrentExecutor` rather than `nil`: a `nil` preference is documented as "no
    /// preference … no impact on execution semantics of the operation", so it would leave the
    /// connection's inherited reactor preference in force and hop nowhere. Naming the global
    /// concurrent executor is the documented way to disable an outer preference, and because
    /// `withTaskExecutorPreference` is scoped, the reactor preference is back in force for the
    /// response write the moment this returns.
    private static func hopped(
        _ responder: any HTTPResponder,
        _ request: HTTPRequest,
        _ body: RequestBody,
        _ context: RequestContext
    ) async -> ServerResponse {
        await withTaskExecutorPreference(globalConcurrentExecutor) {
            await responder.respond(to: request, body: body, context: context)
        }
    }
}
