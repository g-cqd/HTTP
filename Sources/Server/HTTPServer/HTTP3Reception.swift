//
//  HTTP3Reception.swift
//  HTTPServer
//
//  What one engine receive hands back to the stream task that made it (audit R5-P0b).
//
//  Feeding octets to the connection engine produces three separable things, and they are returned as one
//  value because they are only coherent together: the engine's isolation is what makes "this batch was
//  routed" and "this stream is no longer blocked" a single step, so a caller must not be able to take
//  the events and file them later.
//

internal import HTTP3
internal import HTTPCore

/// The result of feeding one stream's octets to the HTTP/3 connection engine.
struct HTTP3Reception {
    /// The events belonging to the stream whose octets these were — everything else has already been
    /// filed against the stream it names, inside the same engine critical section (RFC 9204 §2.1.2).
    let own: [HTTP3Connection.Event]

    /// The outbound actions the engine queued, for the driver to perform on the QUIC connection.
    let actions: [HTTP3Connection.Action]

    /// The streams whose bounded mailbox refused their routed batch, for the driver to retire.
    ///
    /// Never empty-and-forgotten: a refusal has to become a reset (RFC 9114 §8.1 H3_EXCESSIVE_LOAD),
    /// because the alternative is silently dropping a request or a body chunk (CWE-770).
    let overflowed: [QUICStreamID]
}
