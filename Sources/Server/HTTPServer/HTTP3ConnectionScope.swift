//
//  HTTP3ConnectionScope.swift
//  HTTPServer
//
//  Every place one HTTP/3 connection holds state for its streams, bundled into one value (audit R5-P0c).
//
//  Retiring a stream has to touch four things at once: the sans-I/O engine's per-stream record (its
//  parser buffer, decoded request, buffered body against the RFC 9114 §4.1 connection budget, and its
//  slot in the SETTINGS_QPACK_BLOCKED_STREAMS allowance of RFC 9204 §2.1.2), the registry entry that
//  routes output to it, the read deadline armed for it, and the RFC 9114 §8.1 abuse charge the peer owes
//  for abandoning it. Passing those as four separate parameters is what let three rounds of fixes each
//  retire some of them: a caller that only had three in scope could only clean up three.
//
//  Bundling them means the retirement funnel takes one argument, and a caller either has the whole scope
//  or has nothing to retire with. It also doubles as the shutdown registry's handle, because a drain and
//  a force-close need exactly the same four things.
//
//  Standards: RFC 9114 §4.1, §5.2, §8.1; RFC 9204 §2.1.2; RFC 9000 §19.19.
//

internal import HTTPTransport

extension HTTPServer {
    /// The per-connection state one HTTP/3 stream's retirement must reach.
    struct HTTP3ConnectionScope: Sendable {
        /// The QUIC connection itself — for CONNECTION_CLOSE (RFC 9000 §19.19).
        let quic: any QUICConnection
        /// Where engine output for a stream is routed, and where its writer lives.
        let registry: HTTP3StreamRegistry
        /// The serialized sans-I/O connection engine.
        let engine: Engine
        /// The read deadlines armed for this connection's request streams (RFC 9112 §9.3 over §4.1).
        let deadlines: HTTP3StreamDeadlines
    }
}
