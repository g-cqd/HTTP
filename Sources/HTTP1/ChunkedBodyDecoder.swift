//
//  ChunkedBodyDecoder.swift
//  HTTP1
//
//  RFC 9112 §7.1 — a *resumable* chunked transfer-coding decoder. Unlike a one-shot decode, it
//  remembers its position across feeds (the small ``State`` plus a caller-owned body buffer), so each
//  octet is consumed exactly once even when a body arrives in many reads — no O(n²) re-scan of the
//  accumulated buffer (audit H1-F1, CWE-407). The body is passed `inout` separately from ``State`` so
//  it is grown in place, never copied per feed.
//
//  Hardening folded in: cumulative chunk-extension length is bounded (§7.1.1, audit H1-F2) and each
//  trailer field-line is validated like a header line (§7.1.2 / RFC 9110 §5.5, audit H1-F3) instead of
//  being discarded unchecked.
//

public import HTTPCore

/// A resumable decoder for the HTTP/1.1 chunked transfer-coding (RFC 9112 §7.1).
public enum ChunkedBodyDecoder {
    /// The phase of a chunked decode, carried in ``State`` between feeds.
    ///
    /// `fileprivate` (not `private`) so the stepping helpers below can read and switch over it; one
    /// level of nesting keeps it scoped to the decoder without tripping the nesting limit.
    // swiftlint:disable:next strict_fileprivate - shared by State and the stepping helpers in-file
    fileprivate enum Phase: Equatable, Sendable {
        case size  // expecting a chunk-size line
        case data(remaining: Int)  // copying a chunk's data octets
        case dataTerminator  // expecting the CRLF after a chunk's data
        case trailers  // consuming the trailer section
        case complete  // terminating chunk + trailers seen
    }

    /// The carried position of a chunked decode between feeds (a value type; the decoded body is held
    /// by the caller and passed `inout`, so it grows in place without a copy-on-write copy per feed).
    public struct State: Equatable, Sendable {
        // swiftlint:disable:next strict_fileprivate - read and written by ChunkedBodyDecoder in-file
        fileprivate var phase: Phase = .size
        // swiftlint:disable:next strict_fileprivate - read and written by ChunkedBodyDecoder in-file
        fileprivate var extBytes = 0
        // swiftlint:disable:next strict_fileprivate - read and written by ChunkedBodyDecoder in-file
        fileprivate var trailerBytes = 0

        /// Creates a decoder positioned before the first chunk-size line.
        public init() {
            // No initial state beyond the property defaults above.
        }

        /// Whether the terminating zero-size chunk and trailer section have been fully consumed.
        public var isComplete: Bool { phase == .complete }
    }

    private static let cr: UInt8 = 0x0D
    private static let lf: UInt8 = 0x0A
    private static let semicolon: UInt8 = 0x3B
    private static let colon: UInt8 = 0x3A
    private static let space: UInt8 = 0x20
    private static let htab: UInt8 = 0x09

    /// Consumes every complete chunked unit available in `reader`, appending data to `body`.
    ///
    /// Returns `true` once the body is complete; `false` when more input is needed — the reader is left
    /// at the start of the first incomplete unit so the next feed resumes there. Each data octet is
    /// appended exactly once across feeds.
    @discardableResult
    public static func advance(
        _ reader: inout ByteReader,
        state: inout State,
        into body: inout [UInt8],
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> Bool {
        while state.phase != .complete {
            guard try step(&reader, state: &state, into: &body, limits: limits) else {
                return false
            }
        }
        return true
    }

    /// Advances by one unit.
    ///
    /// Returns `false` when more input is needed (resume on the next feed) and `true` when it made
    /// progress (loop again). Splitting the size and trailer arms into helpers keeps complexity low.
    private static func step(
        _ reader: inout ByteReader, state: inout State, into body: inout [UInt8], limits: HTTPLimits
    ) throws(HTTP1ParseError) -> Bool {
        switch state.phase {
            case .complete:
                return true
            case .size:
                return try stepSize(&reader, state: &state, bodyCount: body.count, limits: limits)
            case .data(let remaining):
                let took = copyData(&reader, remaining: remaining, into: &body)
                state.phase =
                    took < remaining ? .data(remaining: remaining - took) : .dataTerminator
                return took == remaining
            case .dataTerminator:
                guard try consumeCRLF(&reader) else {
                    return false
                }
                state.phase = .size
                return true
            case .trailers:
                return try stepTrailers(&reader, state: &state, limits: limits)
        }
    }

    private static func stepSize(
        _ reader: inout ByteReader, state: inout State, bodyCount: Int, limits: HTTPLimits
    ) throws(HTTP1ParseError) -> Bool {
        // A chunk-size line (size + optional chunk-ext) is bounded by `maxFieldSize`; the cumulative
        // chunk-ext budget is enforced separately in `beginChunk` once the whole line is in hand.
        switch try readLine(
            &reader, maxLength: limits.maxFieldSize, ifTooLong: .chunkExtensionTooLarge
        ) {
            case .needMore:
                return false
            case .line(let range):
                try beginChunk(
                    reader.slice(in: range),
                    state: &state,
                    bodyCount: bodyCount,
                    limits: limits
                )
                return true
        }
    }

    private static func stepTrailers(
        _ reader: inout ByteReader, state: inout State, limits: HTTPLimits
    ) throws(HTTP1ParseError) -> Bool {
        switch try consumeTrailer(&reader, state: &state, limits: limits) {
            case .needMore:
                return false
            case .consumed:
                return true
            case .complete:
                state.phase = .complete
                return true
        }
    }

    // MARK: Units

    private enum LineStep {
        case needMore
        case line(Range<Int>)
    }

    /// Reads one CRLF-terminated line, returning the bytes before CRLF and advancing past it.
    ///
    /// Returns `.needMore` (without advancing) until the full CRLF is present; a bare CR is a framing
    /// error. An in-progress line longer than `maxLength` — whether the terminator has not arrived or a
    /// CR has but the preceding line is already over the bound — fails closed with `error`, so a
    /// CRLF-less chunk-size / chunk-ext / trailer line cannot grow the inbound buffer without limit
    /// (audit F-CHUNKBUF; CWE-400/CWE-770).
    private static func readLine(
        _ reader: inout ByteReader, maxLength: Int, ifTooLong error: HTTP1ParseError
    ) throws(HTTP1ParseError) -> LineStep {
        guard let crIndex = reader.firstIndex(of: cr) else {
            guard reader.remaining <= maxLength else { throw error }
            return .needMore
        }
        guard crIndex - reader.position <= maxLength else { throw error }
        let lfIndex = crIndex + 1
        guard lfIndex < reader.count else {
            return .needMore
        }  // CR present, LF not yet
        guard reader.peek(ahead: lfIndex - reader.position) == lf else { throw .malformedChunk }
        let range = reader.position ..< crIndex
        reader.advance(by: lfIndex + 1 - reader.position)
        return .line(range)
    }

    /// Parses a chunk-size line: `chunk-size [ chunk-ext ]`.
    ///
    /// Sets the next phase and bounds the chunk data against `maxBodySize` and the cumulative
    /// chunk-extension length against `maxHeaderListSize`.
    private static func beginChunk(
        _ line: RawSpan, state: inout State, bodyCount: Int, limits: HTTPLimits
    ) throws(HTTP1ParseError) {
        let count = line.byteCount
        var size = 0
        var index = 0
        var sawDigit = false
        var extStart = -1
        while index < count {
            let byte = line.unsafeLoad(fromByteOffset: index, as: UInt8.self)
            if byte == semicolon {
                extStart = index
                break
            }
            guard let digit = hexValue(byte) else { throw .invalidChunkSize }
            let (scaled, scaleOverflow) = size.multipliedReportingOverflow(by: 16)
            guard !scaleOverflow else { throw .invalidChunkSize }
            let (sum, addOverflow) = scaled.addingReportingOverflow(digit)
            guard !addOverflow else { throw .invalidChunkSize }
            size = sum
            sawDigit = true
            index += 1
        }
        guard sawDigit else { throw .invalidChunkSize }
        if extStart >= 0 {
            // A server "ought to limit the total length of chunk extensions" (RFC 9112 §7.1.1); an
            // unbounded extension is a desync/DoS surface. Count octets from ';' to end of line.
            state.extBytes += count - extStart
            guard state.extBytes <= limits.maxHeaderListSize else { throw .chunkExtensionTooLarge }
        }
        if size == 0 {
            state.phase = .trailers
        }
        else {
            // Compare without computing `bodyCount + size`, which would trap on a hostile near-Int.max
            // chunk size; `bodyCount <= maxBodySize` holds by construction (RFC 9112 §7.1).
            guard size <= limits.maxBodySize - bodyCount else { throw .bodyTooLarge }
            state.phase = .data(remaining: size)
        }
    }

    /// Appends up to `remaining` available octets to `body`, returning how many were copied.
    private static func copyData(
        _ reader: inout ByteReader, remaining: Int, into body: inout [UInt8]
    ) -> Int {
        let take = min(remaining, reader.remaining)
        guard take > 0 else {
            return 0
        }
        let start = reader.position
        reader.slice(in: start ..< (start + take)).withUnsafeBytes { body.append(contentsOf: $0) }
        reader.advance(by: take)
        return take
    }

    /// Consumes the CRLF that follows a chunk's data; returns `false` until both octets are present.
    private static func consumeCRLF(_ reader: inout ByteReader) throws(HTTP1ParseError) -> Bool {
        guard reader.remaining >= 2 else {
            return false
        }
        guard reader.peek() == cr, reader.peek(ahead: 1) == lf else { throw .malformedChunk }
        reader.advance(by: 2)
        return true
    }

    private enum TrailerStep { case needMore, consumed, complete }

    /// Consumes one trailer field-line (validating it) or the terminating empty line.
    private static func consumeTrailer(
        _ reader: inout ByteReader, state: inout State, limits: HTTPLimits
    ) throws(HTTP1ParseError) -> TrailerStep {
        // A single trailer field-line is bounded by `maxFieldSize`; the cumulative trailer-section size
        // is enforced separately below once each whole line is in hand.
        switch try readLine(
            &reader, maxLength: limits.maxFieldSize, ifTooLong: .headerSectionTooLarge
        ) {
            case .needMore:
                return .needMore
            case .line(let range):
                // The terminating empty line ends the trailers.
                if range.isEmpty {
                    return .complete
                }
                try validateTrailer(reader.slice(in: range))
                state.trailerBytes += range.count + 2
                guard state.trailerBytes <= limits.maxHeaderListSize else {
                    throw .headerSectionTooLarge
                }
                return .consumed
        }
    }

    /// Validates a trailer field-line like a header field-line (RFC 9112 §7.1.2 / RFC 9110 §5.5):
    /// reject obs-fold, require a `token` name before the colon, and a valid field-value after it.
    private static func validateTrailer(_ line: RawSpan) throws(HTTP1ParseError) {
        let count = line.byteCount
        guard line.unsafeLoad(fromByteOffset: 0, as: UInt8.self) != space,
            line.unsafeLoad(fromByteOffset: 0, as: UInt8.self) != htab
        else { throw .obsoleteLineFolding }
        var colonIndex = -1
        var index = 0
        while index < count {
            if line.unsafeLoad(fromByteOffset: index, as: UInt8.self) == colon {
                colonIndex = index
                break
            }
            index += 1
        }
        guard colonIndex > 0 else { throw .malformedChunk }  // no colon, or an empty field-name
        var name = 0
        while name < colonIndex {
            guard FieldValidation.isTokenByte(line.unsafeLoad(fromByteOffset: name, as: UInt8.self))
            else { throw .invalidFieldName }
            name += 1
        }
        var value = colonIndex + 1
        while value < count {
            guard
                FieldValidation.isFieldValueByte(
                    line.unsafeLoad(fromByteOffset: value, as: UInt8.self)
                )
            else { throw .invalidFieldValue }
            value += 1
        }
    }

    /// The value of a single hexadecimal digit, or `nil` if `byte` is not a HEXDIG.
    private static func hexValue(_ byte: UInt8) -> Int? {
        switch byte {
            case 0x30 ... 0x39:
                Int(byte - 0x30)  // 0-9
            case 0x41 ... 0x46:
                Int(byte - 0x41 + 10)  // A-F
            case 0x61 ... 0x66:
                Int(byte - 0x61 + 10)  // a-f
            default:
                nil
        }
    }
}
