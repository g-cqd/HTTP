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
/// The parser borrows the body as a `RawSpan` and addresses it by offset: it never copies bytes to look
/// at them. Being `~Escapable`, it is statically prevented from outliving that borrow. Bytes become
/// owned values at exactly two points — a part's payload, and the header-derived strings a
/// ``MultipartFormData/Part`` must carry — and nowhere else.
struct MultipartParser: ~Escapable {
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

    static let cr: UInt8 = 0x0D
    static let lf: UInt8 = 0x0A
    static let colon: UInt8 = 0x3A
    static let space: UInt8 = 0x20
    static let tab: UInt8 = 0x09

    private static let dash: UInt8 = 0x2D

    /// The length of the `CRLF CRLF` that separates a part's header section from its payload.
    static let blankLineCount = 4

    let body: RawSpan
    let boundary: MultipartBoundary
    let limits: MultipartLimits

    /// The offset the next delimiter search resumes from.
    ///
    /// It only ever moves forward, which is what keeps the whole parse a single pass over the body.
    private var cursor: Int

    /// Bytes the parts built so far will retain, charged against ``MultipartLimits/maxRetainedBytes``.
    var retained: Int

    /// Byte comparisons the delimiter matcher has performed — the complexity oracle for the tests.
    ///
    /// Knuth-Morris-Pratt guarantees at most `2 × body` of them: the automaton state rises by at most
    /// one per byte read and every retreat strictly lowers it, so retreats can never outnumber reads.
    /// Asserting that bound is a property of the algorithm rather than of the machine, which is why the
    /// linearity test is deterministic instead of a wall-clock ratio that would flake under load.
    private(set) var byteComparisons: Int

    /// Creates a parser over the borrowed `body`, splitting it on `boundary` under `limits`.
    @_lifetime(copy body)
    init(body: RawSpan, boundary: MultipartBoundary, limits: MultipartLimits) {
        self.body = body
        self.boundary = boundary
        self.limits = limits
        self.cursor = 0
        self.retained = 0
        self.byteComparisons = 0
    }

    /// Parses the body into its parts in order, or nil when it is malformed or breaches ``limits``.
    ///
    /// Malformed means: no opening delimiter, or no close-delimiter after the last part. A part that
    /// declares no `Content-Disposition` `name` is skipped rather than failing the whole body, which is
    /// the lenient behaviour RFC 7578 §4.2 implies for unrecognized parts — but a *limit* breach fails
    /// the whole body, because a form parsed from a body the server refused to bound is not a result.
    mutating func parse() -> MultipartFormData? {
        guard var delimiter = openingDelimiter() else {
            return nil
        }
        var parts: [MultipartFormData.Part] = []
        var encountered = 0
        while !delimiter.isClosing {
            guard let next = nextDelimiter() else {
                return nil  // a part was opened but never closed
            }
            encountered += 1
            guard encountered <= limits.maxParts else {
                return nil
            }
            guard append(delimiter.contentStart ..< next.start, to: &parts) else {
                return nil
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
    ///
    /// A `while` rather than `for offset in 0 ..< count`: `for-in` over a `Range` goes through
    /// `IndexingIterator.next()`, one heap allocation per iteration in an unoptimized build. Nothing to
    /// do with the borrowed span — it costs the same in a function that touches no span at all — and
    /// release specializes it away entirely. What it costs is the allocation oracles that guard this
    /// parser, which run in the unoptimized build. Do not "tidy" it back.
    private func opensWithDashBoundary() -> Bool {
        let needle = boundary.delimiter
        let dashBoundaryCount = needle.count - MultipartBoundary.crlfCount
        guard body.byteCount >= dashBoundaryCount else {
            return false
        }
        var offset = 0
        while offset < dashBoundaryCount {
            guard byte(at: offset) == needle[offset + MultipartBoundary.crlfCount] else {
                return false
            }
            offset += 1
        }
        return true
    }

    /// Scans forward from ``cursor`` for the next syntactically valid delimiter, or nil if none remains.
    ///
    /// A Knuth-Morris-Pratt scan: each body byte is loaded exactly once and, on a mismatch, the
    /// automaton retreats through ``MultipartBoundary/failure`` instead of the text rewinding to the
    /// candidate's start. That bounds the whole scan at `2 × body` byte comparisons however many partial
    /// boundary prefixes the peer plants, *unconditionally* — a naive rescan happens to be linear here
    /// too, but only because `bchars` excludes CR, which is a validation policy rather than a property
    /// of the search (CWE-407).
    ///
    /// A `CRLF "--" boundary` occurrence whose suffix fails ``delimiter(startingAt:suffixFrom:)`` is
    /// ordinary part content, so the scan resumes from the automaton state it has already reached
    /// rather than restarting — the reason a flood of junk-suffixed delimiters is linear too.
    private mutating func nextDelimiter() -> Delimiter? {
        let needle = boundary.delimiter
        var index = cursor
        var state = 0
        while index < body.byteCount {
            let byte = byte(at: index)
            index += 1
            while true {
                byteComparisons += 1
                if byte == needle[state] {
                    state += 1
                    break
                }
                if state == 0 {
                    break
                }
                state = Int(boundary.failure[state])
            }
            guard state == needle.count else {
                continue
            }
            if let matched = delimiter(startingAt: index - needle.count, suffixFrom: index) {
                cursor = matched.contentStart
                return matched
            }
            state = Int(boundary.failure[state])
        }
        cursor = body.byteCount
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
        if index + 1 < body.byteCount, byte(at: index) == Self.dash,
            byte(at: index + 1) == Self.dash
        {
            isClosing = true
            index += 2
        }
        while index < body.byteCount, byte(at: index) == Self.space || byte(at: index) == Self.tab {
            index += 1  // transport-padding := *LWSP-char
        }
        if index + 1 < body.byteCount, byte(at: index) == Self.cr, byte(at: index + 1) == Self.lf {
            return Delimiter(start: start, contentStart: index + 2, isClosing: isClosing)
        }
        guard isClosing, index == body.byteCount else {
            return nil
        }
        return Delimiter(start: start, contentStart: index, isClosing: true)
    }

    /// The byte at `index`; every caller derives `index` from a bound already checked against the body.
    func byte(at index: Int) -> UInt8 {
        body.unsafeLoad(fromByteOffset: index, as: UInt8.self)
    }

    /// The bytes of `range` copied into an exactly sized array — one of the two materialization points.
    func bytes(in range: Range<Int>) -> [UInt8] {
        body.extracting(range).withUnsafeBytes { [UInt8]($0) }
    }

    /// The bytes of `range` decoded as UTF-8 — the other materialization point.
    func string(in range: Range<Int>) -> String {
        body.extracting(range).withUnsafeBytes { String(decoding: $0, as: Unicode.UTF8.self) }
    }
}
