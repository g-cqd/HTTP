//
//  MultipartParser+Part.swift
//  HTTPCore
//
//  RFC 7578 §4.2 — one form part: `MIME-part-headers CRLF CRLF body`, where the headers must carry a
//  `Content-Disposition: form-data` with a `name` parameter and may carry a `filename` and a
//  `Content-Type`. Everything here works on offsets into the borrowed body: the header section is never
//  copied, never split into lines as strings, and never collected into a dictionary. Only three values
//  per part outlive the parse — the payload, the `name`, and the optional `filename`/`contentType` —
//  and each is materialized exactly once, after the limit that governs it has been checked.
//

extension MultipartParser {
    /// The two header fields a form part is read for, located as ranges in the borrowed body.
    ///
    /// Every other field is ignored, so nothing is retained for it. A part may legitimately carry
    /// `Content-Transfer-Encoding` or vendor fields; parsing them into a dictionary in order to look up
    /// two names was the bulk of the old per-part allocation.
    struct PartHeaders {
        /// Range of the `Content-Disposition` field value, or nil when the part declares none.
        var disposition: Range<Int>?
        /// Range of the `Content-Type` field value, or nil.
        var contentType: Range<Int>?
    }

    private static let contentDisposition = Array("content-disposition".utf8)
    private static let contentTypeName = Array("content-type".utf8)

    /// Parses `range` as one part's `header-section CRLF CRLF body` (RFC 7578 §4.2) and appends it.
    ///
    /// Returns false to reject the whole body — a per-part header section or an aggregate retained
    /// total over ``MultipartParser/limits``. A part with no blank line (so no header section) or no
    /// `Content-Disposition` `name` is skipped, and returns true: that is leniency, not a breach.
    ///
    /// The order of the steps is the point. The header cap is checked before the header section is
    /// scanned, and the retained cap before the payload is copied, so the bytes a limit refuses are
    /// never allocated in order to discover that they should not have been.
    mutating func append(
        _ range: Range<Int>,
        to parts: inout [MultipartFormData.Part]
    ) -> Bool {
        guard let blankLine = firstIndex(ofBlankLineIn: range) else {
            return true
        }
        let headerRange = range.lowerBound ..< blankLine
        guard headerRange.count <= limits.maxPartHeaderBytes else {
            return false
        }
        let headers = partHeaders(in: headerRange)
        guard let dispositionRange = headers.disposition,
            let name = parameter("name", inValueAt: dispositionRange)
        else {
            return true
        }
        let filename = parameter("filename", inValueAt: dispositionRange)
        let contentType = headers.contentType.map { string(in: $0) }
        let payload = (blankLine + Self.blankLineCount) ..< range.upperBound
        let charge =
            payload.count + name.utf8.count + (filename?.utf8.count ?? 0)
            + (contentType?.utf8.count ?? 0)
        guard retained + charge <= limits.maxRetainedBytes else {
            return false
        }
        retained += charge
        parts.append(
            MultipartFormData.Part(
                name: name,
                filename: filename,
                contentType: contentType,
                body: bytes(in: payload)
            )
        )
        return true
    }

    /// The value of the `name` parameter in the header value at `range` (RFC 2045 §5.1).
    ///
    /// Hands the parameter state machine a borrowed sub-span rather than a `String`, so a part whose
    /// `Content-Disposition` is long does not pay for a copy of it per parameter looked up.
    private func parameter(_ name: String, inValueAt range: Range<Int>) -> String? {
        MultipartParameters.value(of: name, in: body.extracting(range))
    }

    /// Locates the `Content-Disposition` and `Content-Type` values within a part's header section.
    ///
    /// One pass over the section. Lines are split on LF and a trailing CR is dropped, which accepts the
    /// bare-LF line endings some clients emit while RFC 2046 §5.1.1 mandates CRLF.
    private func partHeaders(in range: Range<Int>) -> PartHeaders {
        var headers = PartHeaders()
        var start = range.lowerBound
        while start < range.upperBound {
            var end = start
            while end < range.upperBound, byte(at: end) != Self.lf {
                end += 1
            }
            var lineEnd = end
            if lineEnd > start, byte(at: lineEnd - 1) == Self.cr {
                lineEnd -= 1
            }
            classify(start ..< lineEnd, into: &headers)
            start = end + 1
        }
        return headers
    }

    /// Records `line` in `headers` when it is one of the two fields a form part is read for.
    private func classify(_ line: Range<Int>, into headers: inout PartHeaders) {
        guard let colon = firstIndex(of: Self.colon, in: line) else {
            return
        }
        let name = trimmed(line.lowerBound ..< colon)
        let value = trimmed((colon + 1) ..< line.upperBound)
        if matches(Self.contentDisposition, name) {
            headers.disposition = value
        }
        else if matches(Self.contentTypeName, name) {
            headers.contentType = value
        }
    }

    /// Whether the bytes at `range` are `expected`, compared ASCII-case-insensitively.
    private func matches(_ expected: [UInt8], _ range: Range<Int>) -> Bool {
        guard range.count == expected.count else {
            return false
        }
        var offset = 0
        while offset < expected.count {
            guard lowercased(byte(at: range.lowerBound + offset)) == expected[offset] else {
                return false
            }
            offset += 1
        }
        return true
    }

    /// `byte` lowercased if it is an ASCII letter, else unchanged.
    private func lowercased(_ byte: UInt8) -> UInt8 {
        (0x41 ... 0x5A).contains(byte) ? byte | 0x20 : byte
    }

    /// `range` with leading and trailing LWSP (SP / HTAB) removed.
    private func trimmed(_ range: Range<Int>) -> Range<Int> {
        var lower = range.lowerBound
        var upper = range.upperBound
        while lower < upper, isLWSP(byte(at: lower)) {
            lower += 1
        }
        while upper > lower, isLWSP(byte(at: upper - 1)) {
            upper -= 1
        }
        return lower ..< upper
    }

    /// Whether `byte` is an RFC 822 `LWSP-char` (SP or HTAB).
    private func isLWSP(_ byte: UInt8) -> Bool { byte == Self.space || byte == Self.tab }

    /// The first offset of `needle` within `range`, or nil.
    ///
    /// Every scan here is a `while` rather than a `for` over a `Range`: `for-in` over a `Range` goes
    /// through `IndexingIterator.next()`, one heap allocation per iteration in an unoptimized build, so
    /// the idiomatic spelling costs one malloc per byte of every part header on every debug and test
    /// run. The borrowed span is not what triggers it — an ordinary function iterating a `Range` of
    /// `Int` and touching no span pays exactly the same — and release specializes it away, so this is a
    /// measurement cost rather than a production one. It is worth avoiding anyway: the allocation
    /// oracles for this parser run in the unoptimized build, and per-byte iterator traffic is precisely
    /// what drowns out the per-part copies they exist to catch.
    private func firstIndex(of needle: UInt8, in range: Range<Int>) -> Int? {
        var index = range.lowerBound
        while index < range.upperBound {
            if byte(at: index) == needle {
                return index
            }
            index += 1
        }
        return nil
    }

    /// The offset of the `CRLF CRLF` that ends a part's header section within `range`, or nil.
    private func firstIndex(ofBlankLineIn range: Range<Int>) -> Int? {
        var index = range.lowerBound
        let last = range.upperBound - Self.blankLineCount
        while index <= last {
            if byte(at: index) == Self.cr, byte(at: index + 1) == Self.lf,
                byte(at: index + 2) == Self.cr, byte(at: index + 3) == Self.lf
            {
                return index
            }
            index += 1
        }
        return nil
    }
}
