//
//  AcceptEncoding.swift
//  HTTPServer
//
//  RFC 9110 §12.5.3 — one parse of an `Accept-Encoding` field value into a fixed preference structure,
//  so negotiation is a comparison of quality values rather than a re-scan of the header per candidate.
//
//  The header is a `#( codings [ weight ] )` list and the weight is a `qvalue` (§12.4.2):
//
//      qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
//
//  so `q=0`, `q=0.0`, `q=0.000`, and — parameter names being case-insensitive (§5.6.6) — `Q=0` are all
//  the same refusal. Matching only the literal spelling `q=0` lets the others through and serves a
//  coding the client said it cannot decode. Qualities are kept in thousandths (`Int`), which is exactly
//  the precision the grammar allows and avoids comparing `Double`s that a decimal parse may have
//  rounded apart.
//
//  Two §12.5.3 rules that are easy to lose and are enforced here:
//  - `*` supplies a quality only for codings with no entry of their own, so `*;q=1, br;q=0` still
//    refuses Brotli and `*;q=0, br;q=1` still allows it.
//  - an unencoded representation "is acceptable by default unless specifically excluded ... by either
//    `identity;q=0` or `*;q=0` without a more specific entry for identity".
//
//  A malformed weight (`q=`, `q=2`, `q=1.5`, `q=0.0000`) makes the whole entry unusable rather than
//  silently full quality: honoring the coding while ignoring the part of it we could not read is how a
//  client ends up with bytes it cannot decode.
//

/// One request's parsed `Accept-Encoding` preferences (RFC 9110 §12.5.3).
struct AcceptEncoding {
    /// A content coding this server can serve from a precompressed sidecar.
    enum Coding: String {
        case brotli = "br"
        case gzip

        /// The sidecar filename suffix carrying this coding.
        var suffix: String {
            switch self {
                case .brotli:
                    return ".br"
                case .gzip:
                    return ".gz"
            }
        }
    }

    /// The quality of a coding the client did not object to — `q=1` in thousandths.
    private static let full = 1_000

    private var brotli: Int?
    private var gzip: Int?
    private var identity: Int?
    private var wildcard: Int?

    /// Parses `field`, the combined `Accept-Encoding` value, or nothing when the header is absent.
    ///
    /// An absent header means "any content coding is acceptable" (§12.5.3), but this parse leaves every
    /// coding unrated, so nothing is served coded. That is deliberate: a client that never mentioned a
    /// coding is a client whose decoder has not been demonstrated, and the cost of being wrong is an
    /// undecodable body rather than a few unsaved octets.
    init(_ field: String?) {
        guard let field else {
            return
        }
        for element in field.split(separator: ",", omittingEmptySubsequences: false) {
            record(element)
        }
    }

    /// Files one `codings [ weight ]` list element into the matching slot.
    private mutating func record(_ element: Substring) {
        let separator = element.firstIndex(of: ";")
        let token = Self.trimmed(element[..<(separator ?? element.endIndex)])
        guard !token.isEmpty else {
            return  // an empty element; §12.5.3 tolerates it, it selects nothing
        }
        let parameters =
            separator.map { element[element.index(after: $0)...] } ?? element[element.endIndex...]
        guard let quality = Self.quality(in: parameters) else {
            return  // an unreadable weight leaves the coding unrated
        }
        if Self.matches(token, "br") {
            brotli = quality
        }
        else if Self.matches(token, "gzip") || Self.matches(token, "x-gzip") {
            gzip = quality  // `x-gzip` is the deprecated alias RFC 9110 §8.4.1.3 still recognizes
        }
        else if Self.matches(token, "identity") {
            identity = quality
        }
        else if token == "*" {
            wildcard = quality
        }
    }

    /// The quality the client assigned `coding`, in thousandths; `0` means "not acceptable".
    func quality(of coding: Coding) -> Int {
        let explicit = coding == .brotli ? brotli : gzip
        return explicit ?? wildcard ?? 0
    }

    /// Whether an unencoded representation may be sent (RFC 9110 §12.5.3).
    var identityIsAcceptable: Bool {
        (identity ?? wildcard ?? Self.full) > 0
    }

    /// The sidecar codings worth opening, most preferred first; `nil` where none qualifies.
    ///
    /// Returned as a pair rather than an array so negotiating allocates nothing. A tie goes to Brotli:
    /// equal quality values express no client preference, and §12.5.3 leaves the choice among equally
    /// acceptable representations to the server, which prefers the better ratio.
    var candidates: (first: Coding?, second: Coding?) {
        let ordered =
            quality(of: .brotli) >= quality(of: .gzip)
            ? (Coding.brotli, Coding.gzip) : (Coding.gzip, Coding.brotli)
        return (
            quality(of: ordered.0) > 0 ? ordered.0 : nil,
            quality(of: ordered.1) > 0 ? ordered.1 : nil
        )
    }

    /// The `q=` weight among `parameters` in thousandths, ``full`` when absent, nil when unreadable.
    private static func quality(in parameters: Substring) -> Int? {
        for parameter in parameters.split(separator: ";") {
            let field = trimmed(parameter)
            guard let equals = field.firstIndex(of: "=") else {
                continue  // an extension parameter with no value; §12.5.3 has none, so ignore it
            }
            guard matches(trimmed(field[..<equals]), "q") else {
                continue
            }
            return qvalue(trimmed(field[field.index(after: equals)...]))
        }
        return full
    }

    /// `text` as a `qvalue` in thousandths (RFC 9110 §12.4.2), or nil when it is not one.
    private static func qvalue(_ text: Substring) -> Int? {
        guard let leading = text.first, leading == "0" || leading == "1" else {
            return nil
        }
        let rest = text.dropFirst()
        guard !rest.isEmpty else {
            return leading == "1" ? full : 0
        }
        guard rest.first == "." else {
            return nil
        }
        let digits = rest.dropFirst()
        guard !digits.isEmpty, digits.count <= 3 else {
            return nil  // `0.` and `0.0000` are both outside the grammar
        }
        var thousandths = 0
        var scale = 100
        for digit in digits {
            guard let value = digit.wholeNumberValue, digit.isASCII, (0 ... 9).contains(value)
            else {
                return nil
            }
            thousandths += value * scale
            scale /= 10
        }
        // `1.5` is not a qvalue: only zeros may follow a leading 1.
        guard leading == "0" || thousandths == 0 else {
            return nil
        }
        return leading == "1" ? full : thousandths
    }

    /// Whether `token` equals the lowercase ASCII `name`, ignoring case (RFC 9110 §5.6.6, §8.4.1).
    ///
    /// Compares in place rather than lowercasing, so parsing a header allocates no `String` per entry.
    private static func matches(_ token: Substring, _ name: String) -> Bool {
        token.utf8.count == name.utf8.count
            && zip(token.utf8, name.utf8).allSatisfy { $0 | 0x20 == $1 }
    }

    /// `text` without the leading or trailing SP/HTAB that RFC 9110 §5.6.3 allows around list elements.
    private static func trimmed(_ text: Substring) -> Substring {
        var slice = text
        while let first = slice.first, first == " " || first == "\t" {
            slice = slice.dropFirst()
        }
        while let last = slice.last, last == " " || last == "\t" {
            slice = slice.dropLast()
        }
        return slice
    }
}
