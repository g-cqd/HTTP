//
//  HTTP2StreamingRequest.swift
//  HTTPServer
//
//  An in-flight streaming-route request on an HTTP/2 stream (Phase 1.4, RFC 9113 §8.1): the body-stream
//  continuation the serve loop feeds each decoded DATA chunk into — non-blocking, since the shared
//  multiplexed loop must never block on a handler (the deadlock the response pump also guards against) —
//  and the task running the handler, whose response is sent when the request body ends. Memory is bounded
//  by the per-route body limit the engine enforces before delivery.
//

/// An in-flight HTTP/2 streaming request: the body-stream continuation plus the handler task.
struct HTTP2StreamingRequest {
    /// Yields each decoded request-body chunk to the handler's ``HTTPRequestBodyStream`` (unbounded
    /// buffering — never blocks the serve loop; bounded by the engine's per-route body cap).
    let continuation: AsyncStream<[UInt8]>.Continuation
    /// The task running the handler; its ``ServerResponse`` is sent when the request body ends.
    let task: Task<ServerResponse, Never>
}
