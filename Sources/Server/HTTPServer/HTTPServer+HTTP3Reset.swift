//
//  HTTPServer+HTTP3Reset.swift
//  HTTPServer
//
//  The one way this server abandons an HTTP/3 request stream (audit REG-3).
//
//  ``HTTP3Connection`` is sans-I/O: resetting a QUIC stream on the wire and dropping the registry entry
//  tells it nothing at all. Every path that did only those two things left the engine holding the
//  stream's parser buffer, its decoded request, its buffered body — counted against the connection-wide
//  body budget (RFC 9114 §4.1) — and its slot in the SETTINGS_QPACK_BLOCKED_STREAMS allowance
//  (RFC 9204 §2.1.2), for the life of the connection.
//
//  The read-deadline path (addendum P0.5) was the worst place for that to be true, because it exists to
//  stop exactly this: a peer that opens streams, sends a partial request on each and walks away. Reaping
//  them without retiring the engine turned the defense into the leak. Repeating it was also *free* —
//  ``HTTP3Connection/resetStream(_:errorCode:)`` is what charges the RFC 9114 §8.1 rolling reset budget,
//  the same budget that bounds Rapid Reset (CVE-2023-44487) and MadeYouReset (CVE-2025-8671), and
//  nothing was calling it. That is why it is the right entry point rather than a fresh partial cleanup:
//  the accounting and the state retirement are one operation, and a bespoke cleanup would have re-split
//  them.
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Abandons `id`: reset on the wire, dropped from the registry, retired in the engine.
    ///
    /// Idempotent for the caller's purposes — a stream already retired has no writer to reset and no
    /// engine record to remove, and the abuse budget is charged only for a record that existed, so a
    /// double call cannot double-charge the peer.
    ///
    /// The engine's own actions are flushed afterwards because retiring past the reset budget queues a
    /// CONNECTION_CLOSE carrying H3_EXCESSIVE_LOAD (RFC 9114 §8.1), which only reaches the peer if
    /// somebody drains it.
    func resetHTTP3Stream(
        _ id: QUICStreamID,
        errorCode: UInt64,
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        registry.writer(for: id)?.reset(errorCode: errorCode)
        registry.retire(id)
        let actions = await engine.retire(id, errorCode: errorCode)
        await applyHTTP3(actions, registry: registry, engine: engine, quic: quic)
    }
}
