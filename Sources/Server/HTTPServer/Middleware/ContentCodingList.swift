//
//  ContentCodingList.swift
//  HTTPServer
//
//  RFC 9110 §8.4.1 — `Content-Encoding` is a comma-separated *list* of codings in the order they were
//  applied, not a single token. `Content-Encoding: gzip, br` is a legal request: gzip first, Brotli
//  second, so the wire bytes are `br(gzip(x))` and a decoder must undo them right to left. Treating
//  the field as one token silently mishandles that — comparing the whole value against `"gzip"` fails
//  to match, so the body is forwarded still coded while the header claims otherwise.
//

/// The ordered content codings of a `Content-Encoding` field value (RFC 9110 §8.4.1).
struct ContentCodingList {
    /// The codings in the order they were *applied*, lowercased.
    ///
    /// The last entry is therefore the outermost, and must be decoded first.
    let codings: [String]

    /// Parses a `Content-Encoding` field value, or nil when it is not a well-formed list of at most
    /// `limit` codings.
    ///
    /// Nil covers three cases the caller must not paper over: an empty list, an entry that is not a
    /// token (RFC 9110 §5.6.2 — an empty element, or one carrying a character no coding name may
    /// contain), and a list longer than `limit`, which is CPU amplification bought with one header
    /// (CWE-409). The token check also means the caller can safely write any surviving entries back
    /// into a header field.
    init?(_ value: String, limit: Int) {
        guard limit > 0 else {
            return nil
        }
        var parsed: [String] = []
        parsed.reserveCapacity(limit)
        for element in value.split(separator: ",", omittingEmptySubsequences: false) {
            let coding = Self.trimmingWhitespace(element)
            guard !coding.isEmpty, coding.allSatisfy(Self.isTokenCharacter), parsed.count < limit
            else {
                return nil
            }
            parsed.append(coding.lowercased())
        }
        guard !parsed.isEmpty else {
            return nil
        }
        codings = parsed
    }

    /// `element` without leading or trailing SP/HTAB — the optional whitespace RFC 9110 §5.6.3 allows
    /// around a list element.
    private static func trimmingWhitespace(_ element: Substring) -> Substring {
        var slice = element
        while let first = slice.first, first == " " || first == "\t" {
            slice = slice.dropFirst()
        }
        while let last = slice.last, last == " " || last == "\t" {
            slice = slice.dropLast()
        }
        return slice
    }

    /// Whether `character` is an RFC 9110 §5.6.2 `tchar`.
    private static func isTokenCharacter(_ character: Character) -> Bool {
        character.isASCII
            && (character.isLetter || character.isNumber || "!#$%&'*+-.^_`|~".contains(character))
    }
}
