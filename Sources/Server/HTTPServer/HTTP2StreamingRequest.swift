//
//  HTTP2StreamingRequest.swift
//  HTTPServer
//
//  An in-flight streaming-route request on an HTTP/2 stream (Phase 1.4, RFC 9113 §8.1): the body-stream
//  continuation the merged-mailbox consumer feeds each decoded DATA chunk into — non-blocking, since the
//  shared multiplexed consumer must never block on a handler (the deadlock the response relay also
//  guards against). The handler runs in a dedicated task group child (`HTTPServer.handleHTTP2Event`)
//  that self-reports its ``ServerResponse`` back through the mailbox as a `.requestReady` wakeup once it
//  finishes — unified with the buffered-request path, so a slow streaming-route handler here no longer
//  blocks the consumer from processing the connection's NEXT inbound chunk either. Memory is bounded by
//  the per-route body limit the engine enforces before delivery.
//

/// An in-flight HTTP/2 streaming request: just the body-stream continuation the consumer feeds.
///
/// No handler-task handle is kept: the task is a structured child of the serve loop's task group, so
/// `group.cancelAll()` (the merged-mailbox consumer's one teardown path) already reaps it on every exit,
/// and its response arrives asynchronously as a `.requestReady` wakeup rather than being awaited here.
struct HTTP2StreamingRequest {
    /// Yields each decoded request-body chunk to the handler's ``HTTPRequestBodyStream`` (unbounded
    /// buffering — never blocks the consumer; bounded by the engine's per-route body cap).
    let continuation: AsyncStream<[UInt8]>.Continuation
}
