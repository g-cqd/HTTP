//
//  HTTP2StreamingRequest.swift
//  HTTPServer
//
//  An in-flight streaming-route request on an HTTP/2 stream (Phase 1.4, RFC 9113 §8.1), as the
//  merged-mailbox consumer holds it: the consumption-gated channel it pushes each decoded DATA chunk
//  into, and the signal that channel's reader reports back through.
//
//  The consumer must never block on a handler (it is the engine's single owner, and blocking would stop
//  it processing the WINDOW_UPDATE that unblocks the connection), so it only ever `trySend`s. That is
//  not a drop policy: a refusal is a hard error the consumer escalates to RST_STREAM. In practice it is
//  unreachable, because the receive window already bounds what the peer may have in flight to exactly
//  what this channel can hold — the window IS the watermark (2026-07-31 audit F4, ADR 0006).
//

/// An in-flight HTTP/2 streaming request: the consumption-gated body channel and its report signal.
///
/// No handler-task handle is kept *here*: the task is a structured child of the serve loop's task
/// group, so `group.cancelAll()` (the merged-mailbox consumer's one teardown path) reaps it on every
/// exit, and its response arrives asynchronously as a `.requestReady` wakeup rather than being awaited.
/// A per-stream cancellation handle for the RST_STREAM path is added separately (audit F6).
struct HTTP2StreamingRequest {
    /// Carries each decoded request-body chunk to the handler's ``HTTPRequestBodyStream``.
    ///
    /// Bounded in *bytes* by ``HTTPLimits/streamReceiveWindow``, and never replenished except as the
    /// handler takes chunks out of it — so this queue's depth is a function of handler consumption,
    /// which is precisely what the unbounded `AsyncStream` it replaced was not.
    let channel: BoundedByteChannel

    /// Reports the handler's consumption back to the consumer, which credits the receive windows.
    let signal: HTTP2ConsumptionSignal
}
