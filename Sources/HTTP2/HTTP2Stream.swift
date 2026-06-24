//
//  HTTP2Stream.swift
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

/// A server-side HTTP/2 stream and its RFC 9113 §5.1 state transitions.
public struct HTTP2Stream: Sendable, Equatable {
    /// The stream identifier (RFC 9113 §5.1.1).
    public let id: HTTP2StreamID

    /// The current lifecycle state.
    public private(set) var state: HTTP2StreamState

    /// Creates a stream in the `idle` state.
    public init(id: HTTP2StreamID, state: HTTP2StreamState = .idle) {
        self.id = id
        self.state = state
    }

    /// Applies a received HEADERS frame (request headers, or trailers) — RFC 9113 §5.1.
    public mutating func receiveHeaders(endStream: Bool) throws(HTTP2Error) {
        switch state {
            case .idle:
                state = endStream ? .halfClosedRemote : .open
            case .open:
                // A second HEADERS without END_STREAM is a malformed message — a *stream* error, not a
                // connection error (RFC 9113 §8.1); it must not tear down well-behaved sibling streams.
                guard endStream else {
                    throw .stream(id, .protocolError, "trailers must set END_STREAM")
                }
                state = .halfClosedRemote
            case .halfClosedLocal:
                guard endStream else {
                    throw .stream(id, .protocolError, "trailers must set END_STREAM")
                }
                state = .closed
            case .halfClosedRemote, .closed:
                throw .stream(id, .streamClosed, "HEADERS on a closed stream")
        }
    }

    /// Applies a received DATA frame (request body) — RFC 9113 §5.1.
    public mutating func receiveData(endStream: Bool) throws(HTTP2Error) {
        switch state {
            case .idle:
                throw .connection(.protocolError, "DATA before HEADERS")
            case .open:
                state = endStream ? .halfClosedRemote : .open
            case .halfClosedLocal:
                state = endStream ? .closed : .halfClosedLocal
            case .halfClosedRemote, .closed:
                throw .stream(id, .streamClosed, "DATA on a closed stream")
        }
    }

    /// Applies a sent HEADERS frame (response headers) — RFC 9113 §5.1.
    public mutating func sendHeaders(endStream: Bool) throws(HTTP2Error) {
        switch state {
            case .open:
                state = endStream ? .halfClosedLocal : .open
            case .halfClosedRemote:
                state = endStream ? .closed : .halfClosedRemote
            case .idle, .halfClosedLocal, .closed:
                throw .stream(id, .internalError, "cannot send HEADERS in this state")
        }
    }

    /// Applies a sent DATA frame (response body) — RFC 9113 §5.1.
    public mutating func sendData(endStream: Bool) throws(HTTP2Error) {
        switch state {
            case .open:
                state = endStream ? .halfClosedLocal : .open
            case .halfClosedRemote:
                state = endStream ? .closed : .halfClosedRemote
            case .idle, .halfClosedLocal, .closed:
                throw .stream(id, .internalError, "cannot send DATA in this state")
        }
    }

    /// Closes the stream on RST_STREAM, sent or received (RFC 9113 §5.1 / §6.4).
    public mutating func reset() {
        state = .closed
    }
}
