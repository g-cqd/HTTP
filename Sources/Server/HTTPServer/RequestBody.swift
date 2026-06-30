//
//  RequestBody.swift
//  HTTPServer
//
//  What the responder seam delivers as the request payload: either the fully buffered bytes (today's
//  behavior, and the default the engines produce) or an incremental, back-pressured chunk stream — the
//  request-side mirror of the response's ``ResponseStream``. Modeling the body as a value with both
//  shapes lets a handler that needs the whole payload ask for it buffered, while a handler that wants to
//  process a large upload as it arrives consumes it chunk by chunk, without the seam forcing one choice.
//
//  Streaming production (``stream(_:)``) is wired into the engines in a later phase; until then every
//  request arrives ``collected(_:)``, and the stream accessors already work so the public shape is
//  stable.
//

/// A request body: fully buffered bytes (``collected(_:)``) or an incremental chunk stream
/// (``stream(_:)``).
public enum RequestBody: Sendable {
    /// The whole body, already read into memory — the common case and the engines' current default.
    case collected([UInt8])

    /// An incremental, back-pressured stream of body chunks — consumed as the bytes arrive.
    case stream(HTTPRequestBodyStream)

    /// The body as one buffer: the bytes directly when already ``collected(_:)``, otherwise the stream
    /// drained to completion.
    ///
    /// The buffered entry point for a handler or middleware that needs the whole payload (parsing JSON,
    /// computing a digest); prefer ``asStream`` to process a large body without holding it all in memory.
    public func collect() async -> [UInt8] {
        switch self {
            case .collected(let bytes):
                return bytes
            case .stream(let stream):
                var accumulated: [UInt8] = []
                for await chunk in stream {
                    accumulated.append(contentsOf: chunk)
                }
                return accumulated
        }
    }

    /// The body as an incremental chunk stream: the stream itself when ``stream(_:)``, otherwise a
    /// one-shot stream that yields the already-buffered bytes once.
    ///
    /// Named `asStream` rather than `stream` because the latter is the enum case.
    public var asStream: HTTPRequestBodyStream {
        switch self {
            case .stream(let stream):
                return stream
            case .collected(let bytes):
                return HTTPRequestBodyStream(yielding: bytes)
        }
    }

    /// The already-buffered bytes when ``collected(_:)``, else `nil` — a synchronous peek that never
    /// drains a stream.
    public var bytes: [UInt8]? {
        guard case .collected(let bytes) = self else {
            return nil
        }
        return bytes
    }

    /// Whether the body is delivered incrementally (``stream(_:)``) rather than buffered.
    public var isStreaming: Bool {
        guard case .stream = self else {
            return false
        }
        return true
    }
}
