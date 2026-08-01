//
//  HTTPServer+HTTP3Uni.swift
//  HTTPServer
//
//  The serve loop for a *peer* unidirectional stream — the control stream and the QPACK encoder /
//  decoder streams (RFC 9114 §6.2, RFC 9204 §4.2), plus the reserved types §6.2 says to tolerate.
//
//  These are not request streams and they are deliberately not driven like one. They are long-lived by
//  design: they open once, stay open for the connection's life, and are *idle* whenever no settings or
//  table updates flow — which on a quiet connection is almost always. They carry no request, so there
//  is no claim latch, no routed mailbox, no tunnel state and, above all, no read deadline: the RFC 9112
//  §9.3 Slowloris budgets exist to bound a half-sent *request* (RFC 9114 §4.1), and arming one here
//  reaped the control and QPACK streams of a perfectly healthy connection after `headerReadTimeout`.
//  Driving them through the request loop is what made that mistake expressible at all.
//
//  What they do own is the opposite escalation. RFC 9114 §6.2.1: "If either control stream is closed at
//  any point, this MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM." So a
//  critical stream that ends is a *connection* fault, not a routine per-stream reset — and it does not
//  matter whether it ended with a FIN or with a transport EOF, because §6.2.1 is about the closure, not
//  about how it was spelled. The engine already makes that call for the streams it classified as
//  critical, so this loop feeds it the end of stream and lets it decide.
//
//  Standards: RFC 9114 §6.2, §6.2.1, §8.1; RFC 9204 §4.2; RFC 9000 §2.1 (stream id classes).
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Serves one peer-initiated unidirectional stream until it ends (RFC 9114 §6.2).
    ///
    /// Reads inline rather than through an ``HTTP3StreamInbox``: engine output is addressed by stream id
    /// and never names a unidirectional stream, so this loop has exactly one work source and needs no
    /// merged mailbox. Its receives *produce* routed events for request streams — an encoder-stream
    /// insert unblocking a field section (RFC 9204 §2.1.2) — which the engine files against those
    /// streams as it surfaces them.
    func serveHTTP3PeerUniStream(
        _ stream: any QUICStream,
        in scope: HTTP3ConnectionScope
    ) async {
        var ended = false
        while !ended, let chunk = try? await stream.receive() {
            ended = chunk.fin
            _ = await receiveHTTP3(stream.id, chunk.bytes, fin: chunk.fin, in: scope)
        }
        if !ended {
            // The peer's stream ended without a FIN — a receive fault or a transport EOF. Tell the
            // engine the stream is over anyway: for a critical stream that is the RFC 9114 §6.2.1
            // H3_CLOSED_CRITICAL_STREAM connection error, and for a reserved one it is a no-op.
            _ = await receiveHTTP3(stream.id, [], fin: true, in: scope)
        }
        // Only the routing entry: a unidirectional stream has no wire reset to send (§6.2.1 escalates
        // to the connection instead) and no request-stream state for the retirement funnel to charge —
        // which is why it never goes near ``retireHTTP3Stream(_:errorCode:in:)``, and why that call
        // refuses an id that is not client-initiated bidirectional.
        scope.registry.retire(stream.id)
    }
}
