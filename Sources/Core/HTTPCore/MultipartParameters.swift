//
//  MultipartParameters.swift
//  HTTPCore
//
//  RFC 2045 §5.1 — the `; attribute=value` parameter list carried by `Content-Type` and, for a form
//  part, `Content-Disposition` (RFC 7578 §4.2):
//
//      parameter     := attribute "=" value
//      value         := token / quoted-string
//      quoted-string := <"> *(qtext / quoted-pair) <">
//      quoted-pair   := "\" CHAR
//
//  A quoted-string may contain ANY character, `;` and `"` included. Splitting the list on every
//  semicolon therefore truncates a legitimate `filename="a;b.txt"` and, more seriously, lets a crafted
//  filename inject a `name=` parameter that a strict reader would never see — the two readers then
//  disagree about which form field an upload belongs to (CWE-444, inconsistent interpretation).
//  Zero-dependency and trap-free: an unterminated quote or a missing `=` yields nil, never a trap.
//

/// RFC 2045 §5.1 parameter-list parsing for `Content-Type` and `Content-Disposition` values.
enum MultipartParameters {
    private static let quote: UInt8 = 0x22
    private static let semicolon: UInt8 = 0x3B
    private static let backslash: UInt8 = 0x5C
    private static let equals: UInt8 = 0x3D
    private static let space: UInt8 = 0x20
    private static let tab: UInt8 = 0x09

    /// The value of the `name` parameter in `header`, unquoted and unescaped, or nil when absent.
    ///
    /// The first parameter whose attribute matches wins, matching ASCII-case-insensitively as RFC 2045
    /// §5.1 requires. Borrows `header`'s UTF-8 without copying it.
    static func value(of name: String, in header: String) -> String? {
        var header = header
        return header.withUTF8 { utf8 in
            value(of: name, in: UnsafeRawBufferPointer(utf8).bytes)
        }
    }

    /// The value of the `name` parameter in the borrowed header bytes, unquoted and unescaped.
    static func value(of name: String, in header: RawSpan) -> String? {
        var index = 0
        while index < header.byteCount {
            let segment = nextSegment(in: header, from: &index)
            if let found = value(of: name, inSegment: segment, of: header) {
                return found
            }
        }
        return nil
    }

    /// The next `;`-terminated segment starting at `index`, advancing `index` past that semicolon.
    ///
    /// This is the whole state machine: a `;` counts as a separator only outside a quoted-string, and a
    /// `quoted-pair` suppresses the meaning of the character it precedes — so the closing quote of
    /// `"a\"b"` is the last one, not the escaped one. The leading segment (a media type or a
    /// disposition type) carries no `=` and is skipped by the caller for free.
    private static func nextSegment(in header: RawSpan, from index: inout Int) -> Range<Int> {
        let start = index
        var isQuoted = false
        var isEscaped = false
        while index < header.byteCount {
            let byte = header.unsafeLoad(fromByteOffset: index, as: UInt8.self)
            index += 1
            if isEscaped {
                isEscaped = false
            }
            else if isQuoted {
                isEscaped = byte == backslash
                isQuoted = byte != quote
            }
            else if byte == quote {
                isQuoted = true
            }
            else if byte == semicolon {
                return start ..< (index - 1)
            }
        }
        return start ..< index
    }

    /// The value of `name` if `segment` is its `attribute=value` pair, else nil.
    private static func value(
        of name: String,
        inSegment segment: Range<Int>,
        of header: RawSpan
    ) -> String? {
        // The attribute is a `token`, from which RFC 2045 §5.1 excludes `=`, so the first `=` in the
        // segment always separates attribute from value.
        guard let separator = firstIndex(of: equals, in: header, within: segment) else {
            return nil
        }
        let attribute = trimmed(segment.lowerBound ..< separator, in: header)
        guard matches(name, attribute, in: header) else {
            return nil
        }
        return unquoted(trimmed((separator + 1) ..< segment.upperBound, in: header), in: header)
    }

    /// The bytes of `range` as a `String`, with a surrounding `quoted-string` decoded if present.
    private static func unquoted(_ range: Range<Int>, in header: RawSpan) -> String {
        guard !range.isEmpty, byte(at: range.lowerBound, in: header) == quote else {
            return string(range, in: header)  // a bare `token` value
        }
        var index = range.lowerBound + 1
        var hasEscape = false
        while index < range.upperBound {
            let byte = byte(at: index, in: header)
            if byte == quote {
                break
            }
            if byte == backslash {
                // A quoted-pair consumes the next character, which may itself be the quote byte.
                hasEscape = true
                index += 1
            }
            index += 1
        }
        let content = (range.lowerBound + 1) ..< min(index, range.upperBound)
        return hasEscape ? unescaped(content, in: header) : string(content, in: header)
    }

    /// The bytes of `range` with every `quoted-pair` backslash removed (RFC 2045 §5.1).
    private static func unescaped(_ range: Range<Int>, in header: RawSpan) -> String {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(range.count)
        var index = range.lowerBound
        while index < range.upperBound {
            let byte = byte(at: index, in: header)
            index += 1
            if byte == backslash, index < range.upperBound {
                bytes.append(self.byte(at: index, in: header))
                index += 1
            }
            else {
                bytes.append(byte)
            }
        }
        return String(decoding: bytes, as: Unicode.UTF8.self)
    }

    /// Whether `range` holds `name`, compared ASCII-case-insensitively (RFC 2045 §5.1).
    private static func matches(_ name: String, _ range: Range<Int>, in header: RawSpan) -> Bool {
        var index = range.lowerBound
        for expected in name.utf8 {
            guard index < range.upperBound else {
                return false
            }
            guard lowercased(byte(at: index, in: header)) == lowercased(expected) else {
                return false
            }
            index += 1
        }
        return index == range.upperBound
    }

    /// `byte` lowercased if it is an ASCII letter, else unchanged.
    private static func lowercased(_ byte: UInt8) -> UInt8 {
        (0x41 ... 0x5A).contains(byte) ? byte | 0x20 : byte
    }

    /// `range` with leading and trailing LWSP (SP / HTAB) removed.
    private static func trimmed(_ range: Range<Int>, in header: RawSpan) -> Range<Int> {
        var lower = range.lowerBound
        var upper = range.upperBound
        while lower < upper, isLWSP(byte(at: lower, in: header)) {
            lower += 1
        }
        while upper > lower, isLWSP(byte(at: upper - 1, in: header)) {
            upper -= 1
        }
        return lower ..< upper
    }

    /// Whether `byte` is an RFC 822 `LWSP-char` (SP or HTAB).
    private static func isLWSP(_ byte: UInt8) -> Bool { byte == space || byte == tab }

    /// The first offset of `needle` within `range`, or nil.
    ///
    /// Written as a `while` rather than `for index in range`: `for-in` over a `Range` goes through
    /// `IndexingIterator.next()`, one heap allocation per iteration in an unoptimized build, which is
    /// real cost on every debug and test run and shows up directly in the allocation guards. The
    /// borrowed span is incidental — the same loop over a `Range` of `Int` in a function with no span
    /// costs the same — and release specializes it away, so the cost is to the oracles, not to serving.
    private static func firstIndex(
        of needle: UInt8,
        in header: RawSpan,
        within range: Range<Int>
    ) -> Int? {
        var index = range.lowerBound
        while index < range.upperBound {
            if byte(at: index, in: header) == needle {
                return index
            }
            index += 1
        }
        return nil
    }

    /// The byte at `index`; callers only ever pass offsets inside the borrowed span.
    private static func byte(at index: Int, in header: RawSpan) -> UInt8 {
        header.unsafeLoad(fromByteOffset: index, as: UInt8.self)
    }

    /// The bytes of `range` decoded as UTF-8 — the one point where a parameter becomes owned.
    private static func string(_ range: Range<Int>, in header: RawSpan) -> String {
        header.extracting(range).withUnsafeBytes { String(decoding: $0, as: Unicode.UTF8.self) }
    }
}
