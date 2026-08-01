//
//  HTTPServer+HTTP3Reset.swift
//  HTTPServer
//
//  The one way this server lets go of an HTTP/3 request stream (audit REG-3, R5-P0c).
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
//  Two rounds of fixes then routed *the exits their own tests drove* through it — the deadline lapse,
//  then the truncated upload — and left the receive fault, the peer EOF, the mailbox refusal and the
//  refused tunnel each doing their own partial cleanup. So the funnel is no longer something a caller
//  opts into. ``withHTTP3RequestStream(_:in:_:)`` wraps every driver of a request stream and its body
//  must *return* an ``HTTP3StreamExit``: there is no way to leave without naming an ending, and every
//  ending goes through the same sweep.
//
//  Not a `defer`, though not for the reason first recorded here: `defer` *can* await on this toolchain
//  (Swift 6.4 — verified, not assumed). The reason is that a `defer` cannot make the body NAME its
//  ending. It would need a `var exit` assigned before each return, which is precisely the convention
//  this shape exists to remove — and the four exits that skipped cleanup did so by forgetting exactly
//  that kind of step.
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Drives one request stream and retires it however the driver ends.
    ///
    /// `drive` cannot return without naming an ``HTTP3StreamExit``, and every exit lands in the same
    /// conclusion — so a new way for a stream to end cannot skip retirement by construction rather
    /// than by remembering to call something.
    func withHTTP3RequestStream(
        _ id: QUICStreamID,
        in scope: HTTP3ConnectionScope,
        _ drive: () async -> HTTP3StreamExit
    ) async {
        await concludeHTTP3Stream(id, exit: await drive(), in: scope)
    }

    /// Retires `id` unless something is still owed on it (audit R5-P0c).
    ///
    /// A stream whose engine still holds a QPACK-blocked field section, or whose registry mailbox still
    /// holds routed events, is *parked* for the connection dispatcher rather than retired: its request
    /// has not surfaced yet and will do so from another stream's receive (RFC 9204 §2.1.2). That
    /// decision is one actor-isolated step, so it cannot interleave with the routing that would
    /// invalidate it (R5-P0b). Everything else is retired.
    private func concludeHTTP3Stream(
        _ id: QUICStreamID,
        exit: HTTP3StreamExit,
        in scope: HTTP3ConnectionScope
    ) async {
        scope.deadlines.disarm(id)
        // Taken *before* the decision, because deciding to retire is what removes the entry the writer
        // lives on — and the peer still has to be told (RFC 9114 §8.1). Looking it up afterwards found
        // nothing, so an abandoned stream was silently retired without ever being reset on the wire.
        let writer = scope.registry.writer(for: id)
        guard await !concludeHTTP3Driving(id, registry: scope.registry, engine: scope.engine) else {
            return
        }
        // Only an abandonment is announced. A stream that was answered has already been FINned, and a
        // RESET_STREAM after a clean end tells the peer its completed request failed (RFC 9000 §3.2).
        if case .abandoned(let code) = exit {
            writer?.reset(errorCode: code)
        }
        await retireHTTP3Stream(id, errorCode: exit.errorCode, in: scope)
    }

    /// Abandons `id`: disarmed, reset on the wire, dropped from the registry, retired in the engine.
    ///
    /// Idempotent for the caller's purposes — a stream already retired has no deadline to disarm, no
    /// writer to reset and no engine record to remove, and the abuse budget is charged only for a
    /// record that existed, so a double call cannot double-charge the peer. That is what makes it safe
    /// to run on the *normal* path too: a stream whose response was written leaves nothing behind, so
    /// the sweep proves the retirement rather than assuming it.
    ///
    /// Refuses a stream that is not client-initiated bidirectional. The control and QPACK streams are
    /// long-lived by design (RFC 9114 §6.2) and their closure is a *connection* error under §6.2.1, not
    /// a per-stream reset — so "retire this stream" is not an operation that exists for them, and the
    /// type of the id is what says so.
    ///
    /// The engine's own actions are flushed afterwards because retiring past the reset budget queues a
    /// CONNECTION_CLOSE carrying H3_EXCESSIVE_LOAD (RFC 9114 §8.1), which only reaches the peer if
    /// somebody drains it.
    func retireHTTP3Stream(
        _ id: QUICStreamID,
        errorCode: UInt64,
        in scope: HTTP3ConnectionScope
    ) async {
        guard id.kind == .clientBidirectional else {
            return
        }
        scope.deadlines.disarm(id)
        scope.registry.writer(for: id)?.reset(errorCode: errorCode)
        scope.registry.retire(id)
        let actions = await scope.engine.retire(id, errorCode: errorCode)
        await applyHTTP3(actions, in: scope)
    }
}
