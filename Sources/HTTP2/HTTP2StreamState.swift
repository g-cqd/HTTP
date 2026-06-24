//
//  HTTP2StreamState.swift
//  HTTP2
//
//  RFC 9113 §5.1 — the stream state machine. A server-side stream walks idle → open →
//  half-closed (remote) → closed as the client sends its request and the server its response; the
//  reserved (push) states are omitted because this server does not push. Each transition validates
//  the frame against the current state, failing with the §5.1-mandated scope: a frame in the idle
//  state is a connection error (PROTOCOL_ERROR), while trailers without END_STREAM (a malformed
//  message, §8.1) and a frame on a closed stream are stream errors (PROTOCOL_ERROR / STREAM_CLOSED).
//

/// The lifecycle state of an HTTP/2 stream (RFC 9113 §5.1; push/reserved states omitted).
public enum HTTP2StreamState: Sendable, Equatable {
    /// No frames exchanged yet.
    case idle
    /// Both peers may send (the request is in flight).
    case open
    /// The client finished sending (END_STREAM received); the server still owes a response.
    case halfClosedRemote
    /// The server finished sending (END_STREAM sent); the client may still send.
    case halfClosedLocal
    /// The stream is finished.
    case closed
}
