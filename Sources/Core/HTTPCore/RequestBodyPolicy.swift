//
//  RequestBodyPolicy.swift
//  HTTPCore
//
//  How a sans-I/O engine must treat one request's body, decided from its head: the size ceiling to
//  enforce before any octet is buffered (RFC 9110 §15.5.14), and whether the body is surfaced
//  incrementally or as one buffered request.
//
//  Both facts come from the same route match, so they travel together. They used to reach the HTTP/2
//  and HTTP/3 engines as two independent `@Sendable (HTTPRequest) -> …` closures, which meant the
//  engine asked the routing table the same question twice per request head — half of the redundant
//  matching the 2026-07-31 audit's finding 19 measured. One closure, one answer, one table walk.
//

/// The body-handling policy for one request, decided from its head before any body octet is accepted.
public struct RequestBodyPolicy: Sendable {
    /// The maximum body size in octets, or `nil` to fall back to the global ``HTTPLimits/maxBodySize``.
    ///
    /// A route's limit *replaces* the global bound rather than tightening it — it may raise it as well
    /// as lower it (RFC 9110 §15.5.14 leaves the ceiling to the server).
    public var limit: Int?

    /// Whether the body is surfaced incrementally (`requestHead` → `requestBodyChunk` → `requestEnd`)
    /// rather than buffered into one `request` event.
    public var isStreaming: Bool

    /// The policy for a request no route matched: the global body bound, buffered.
    public static let unmatched = Self()

    /// Creates a body policy.
    public init(limit: Int? = nil, isStreaming: Bool = false) {
        self.limit = limit
        self.isStreaming = isStreaming
    }
}
