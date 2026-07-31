//
//  MultipartParser.swift
//  HTTPCore
//
//  RFC 2046 §5.1.1 — the delimiter grammar that splits a `multipart/form-data` body (RFC 7578) into
//  parts:
//
//      multipart-body    := [preamble CRLF] dash-boundary transport-padding CRLF
//                           body-part *encapsulation close-delimiter transport-padding [CRLF epilogue]
//      dash-boundary     := "--" boundary
//      delimiter         := CRLF dash-boundary
//      close-delimiter   := delimiter "--"
//      transport-padding := *LWSP-char
//
//  The suffix rule is the security-relevant half. `CRLF "--" boundary` may be followed ONLY by
//  transport padding and CRLF, or by `--` for the close-delimiter. A parser that instead looks for the
//  next CRLF anywhere after the boundary accepts `\r\n--boundaryJUNK\r\n` as a delimiter, letting an
//  uploader forge a part split inside their own file bytes and smuggle a second `Content-Disposition`
//  past any content inspection that ran on the same body (CWE-444, inconsistent interpretation of an
//  HTTP request).
//

/// Splits a `multipart/form-data` body into parts using the RFC 2046 §5.1.1 delimiter grammar.
///
/// The parser never copies the body to scan it: every position is an index into the caller's buffer,
/// and bytes become owned values only where a ``MultipartFormData/Part`` must outlive the parse.
struct MultipartParser {
    /// One matched delimiter — where it starts, whether it closes the body, and where the next part
    /// would begin.
    struct Delimiter {
        /// Offset of the delimiter's first byte: its CRLF, or the `-` of an opening `dash-boundary`.
        let start: Int
        /// Offset just past the delimiter line's terminating CRLF — where the next part's bytes begin.
        let contentStart: Int
        /// Whether this is the `close-delimiter` (`delimiter "--"`), which ends the body.
        let isClosing: Bool
    }

    private static let cr: UInt8 = 0x0D
    private static let lf: UInt8 = 0x0A
    private static let dash: UInt8 = 0x2D
    private static let space: UInt8 = 0x20
    private static let tab: UInt8 = 0x09

    private let body: [UInt8]
    private let boundary: MultipartBoundary

    /// The offset the next delimiter search resumes from.
    ///
    /// It only ever moves forward, which is what keeps the whole parse a single pass over the body.
    private var cursor: Int

    /// Creates a parser over `body`, splitting it on `boundary`.
    init(body: [UInt8], boundary: MultipartBoundary) {
        self.body = body
        self.boundary = boundary
        self.cursor = 0
    }

    /// Parses the body into its parts in order, or nil when the delimiter structure is malformed.
    ///
    /// Malformed means: no opening delimiter, or no close-delimiter after the last part. A part that
    /// declares no `Content-Disposition` `name` is skipped rather than failing the whole body, which is
    /// the lenient behaviour RFC 7578 §4.2 implies for unrecognized parts.
    mutating func parse() -> MultipartFormData? {
        guard var delimiter = openingDelimiter() else {
            return nil
        }
        var parts: [MultipartFormData.Part] = []
        while !delimiter.isClosing {
            guard let next = nextDelimiter() else {
                return nil  // a part was opened but never closed
            }
            if let part = part(in: delimiter.contentStart ..< next.start) {
                parts.append(part)
            }
            delimiter = next
        }
        return MultipartFormData(parts: parts)
    }

    /// The body's first delimiter: a `dash-boundary` at offset zero, or a full `delimiter` after a
    /// preamble (RFC 2046 §5.1.1 — the preamble is arbitrary text a non-MIME reader would display).
    private mutating func openingDelimiter() -> Delimiter? {
        let dashBoundaryCount = boundary.delimiter.count - MultipartBoundary.crlfCount
        if opensWithDashBoundary(),
            let opening = delimiter(startingAt: 0, suffixFrom: dashBoundaryCount)
        {
            cursor = opening.contentStart
            return opening
        }
        cursor = 0
        return nextDelimiter()
    }

    /// Whether the body opens with `dash-boundary`, i.e. the delimiter minus its leading CRLF.
    private func opensWithDashBoundary() -> Bool {
        let needle = boundary.delimiter
        let dashBoundaryCount = needle.count - MultipartBoundary.crlfCount
        guard body.count >= dashBoundaryCount else {
            return false
        }
        for offset in 0 ..< dashBoundaryCount
        where body[offset] != needle[offset + MultipartBoundary.crlfCount] {
            return false
        }
        return true
    }

    /// Scans forward from ``cursor`` for the next syntactically valid delimiter, or nil if none remains.
    ///
    /// A `CRLF "--" boundary` occurrence whose suffix fails ``delimiter(startingAt:suffixFrom:)`` is
    /// ordinary part content, so the scan continues past it rather than splitting there.
    private mutating func nextDelimiter() -> Delimiter? {
        while let start = firstIndex(ofDelimiterFrom: cursor) {
            cursor = start + boundary.delimiter.count
            if let matched = delimiter(startingAt: start, suffixFrom: cursor) {
                cursor = matched.contentStart
                return matched
            }
        }
        return nil
    }

    /// Validates the bytes at `end` as a delimiter suffix and returns the delimiter starting at `start`.
    ///
    /// `CRLF "--" boundary` becomes a delimiter only when followed by `transport-padding CRLF`, or by
    /// `"--" transport-padding` for the close-delimiter — whose trailing CRLF is optional because
    /// RFC 2046 §5.1.1 spells the epilogue `[CRLF epilogue]`, so a body may end at the closing dashes.
    private func delimiter(startingAt start: Int, suffixFrom end: Int) -> Delimiter? {
        var index = end
        var isClosing = false
        if index + 1 < body.count, body[index] == Self.dash, body[index + 1] == Self.dash {
            isClosing = true
            index += 2
        }
        while index < body.count, body[index] == Self.space || body[index] == Self.tab {
            index += 1  // transport-padding := *LWSP-char
        }
        if index + 1 < body.count, body[index] == Self.cr, body[index + 1] == Self.lf {
            return Delimiter(start: start, contentStart: index + 2, isClosing: isClosing)
        }
        guard isClosing, index == body.count else {
            return nil
        }
        return Delimiter(start: start, contentStart: index, isClosing: true)
    }

    /// Parses one part's `header-section CRLF CRLF body` (RFC 7578 §4.2) from `range`.
    ///
    /// Returns nil when the part carries no blank line (so no header section at all) or declares no
    /// `Content-Disposition` `name`; the caller skips it.
    private func part(in range: Range<Int>) -> MultipartFormData.Part? {
        MultipartFormData.parsePart(Array(body[range]))
    }

    /// The offset of the first `CRLF "--" boundary` occurrence at or after `start`, or nil.
    private func firstIndex(ofDelimiterFrom start: Int) -> Int? {
        let needle = boundary.delimiter
        guard body.count >= needle.count else {
            return nil
        }
        var index = max(0, start)
        let last = body.count - needle.count
        while index <= last {
            var matched = 0
            while matched < needle.count, body[index + matched] == needle[matched] {
                matched += 1
            }
            if matched == needle.count {
                return index
            }
            index += 1
        }
        return nil
    }
}
