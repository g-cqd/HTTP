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

    /// The largest up-front reservation a declared body length may cause, in octets.
    ///
    /// A declared `Content-Length` is the *peer's claim*, and a claim costs the sender one header
    /// field. Reserving it outright would let a request that never sends a byte commit the whole cap
    /// (CWE-770), so the reservation is capped here and anything beyond it is reached by the array's
    /// own geometric growth — amortized O(*n*) with a logarithmic number of reallocations, which is
    /// the right trade against an attacker-priced allocation.
    static let maxReservation = 1 << 20

    /// The body as one buffer: the bytes directly when already ``collected(_:)``, otherwise the stream
    /// drained to completion.
    ///
    /// Unbounded — it retains whatever the engine delivers. Prefer
    /// ``collect(maximum:expecting:)``, which fails closed at a cap the caller states, or ``asStream``
    /// to process a large body without holding it all in memory.
    public func collect() async -> [UInt8] {
        await collect(maximum: .max, expecting: nil) ?? []
    }

    /// The body as one buffer, refusing to retain more than `maximum` octets.
    ///
    /// Returns `nil` — having *stopped reading* — as soon as the accumulated body would cross
    /// `maximum`, so an over-limit body is never materialized before being refused (RFC 9110
    /// §15.5.14: the caller answers `413 Content Too Large`). `expecting` is the declared body length
    /// (a `Content-Length`) when one is known: it seeds the buffer so a legitimate body is not grown
    /// chunk by chunk, clamped to ``maxReservation`` because the claim is attacker-supplied.
    public func collect(maximum: Int, expecting expectedCount: Int? = nil) async -> [UInt8]? {
        guard maximum >= 0 else {
            return nil
        }
        switch self {
            case .collected(let bytes):
                return bytes.count <= maximum ? bytes : nil
            case .stream(let stream):
                return await Self.drain(stream, maximum: maximum, expecting: expectedCount)
        }
    }

    /// Drains `stream` into one buffer, returning nil the moment the total would cross `maximum`.
    private static func drain(
        _ stream: HTTPRequestBodyStream,
        maximum: Int,
        expecting expectedCount: Int?
    ) async -> [UInt8]? {
        var accumulated: [UInt8] = []
        if let expectedCount, expectedCount > 0 {
            accumulated.reserveCapacity(min(expectedCount, maximum, maxReservation))
        }
        for await chunk in stream {
            // `maximum - chunk.count` rather than `accumulated.count + chunk.count`: the first guard
            // proves the subtraction is non-negative, while the addition could overflow on a chunk
            // count near `Int.max`.
            guard chunk.count <= maximum, accumulated.count <= maximum - chunk.count else {
                return nil
            }
            accumulated.append(contentsOf: chunk)
        }
        return accumulated
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
