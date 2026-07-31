//
//  HTTP3RoutedEvents.swift
//  HTTPServer
//
//  One batch of HTTP/3 engine events addressed to a stream *other* than the one whose bytes provoked
//  them (audit addendum P0.3) — the unit the per-connection dispatcher moves from the stream task that
//  made the engine call to the task or writer that owns the stream the events name.
//

internal import HTTP3
internal import HTTPCore

/// Engine events belonging to `streamID`, produced while feeding a different stream.
struct HTTP3RoutedEvents: Sendable {
    /// The stream the events belong to (RFC 9114 §6.1).
    let streamID: QUICStreamID
    /// The events, in the order the engine surfaced them.
    let events: [HTTP3Connection.Event]
}
