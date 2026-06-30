//
//  MultipartFormData.swift
//  HTTPCore
//
//  RFC 7578 — `multipart/form-data` request bodies: a sequence of parts separated by a `--boundary`
//  delimiter (RFC 2046 §5.1), each a small header section (`Content-Disposition` naming the field, plus
//  an optional `Content-Type`) followed by its raw bytes. Parsing is lenient and trap-free: a malformed
//  body returns `nil` rather than crashing, so an attacker-controlled upload never traps the parser.
//  Zero-dependency (no Foundation); the boundary is read from the request's `Content-Type` (§4.1).
//

/// A parsed `multipart/form-data` body (RFC 7578): its form parts, in order.
public struct MultipartFormData: Sendable, Equatable {
    /// One form part: its field `name`, an optional `filename` (a file upload), an optional declared
    /// `Content-Type`, and its raw body bytes (RFC 7578 §4.2).
    public struct Part: Sendable, Equatable {
        /// The form field name (the `Content-Disposition` `name` parameter, RFC 7578 §4.2).
        public var name: String
        /// The uploaded file's name (the `filename` parameter), or `nil` for a non-file field.
        public var filename: String?
        /// The part's declared `Content-Type`, or `nil` if it carried none.
        public var contentType: String?
        /// The part's raw body bytes.
        public var body: [UInt8]

        /// Creates a form part.
        public init(
            name: String,
            filename: String? = nil,
            contentType: String? = nil,
            body: [UInt8]
        ) {
            self.name = name
            self.filename = filename
            self.contentType = contentType
            self.body = body
        }
    }

    /// The parts, in the order they appeared.
    public var parts: [Part]

    /// Creates a multipart body from `parts`.
    public init(parts: [Part]) {
        self.parts = parts
    }

    /// The first part named `name` (a form field may repeat; this returns the first), or `nil`.
    public subscript(_ name: String) -> Part? { parts.first { $0.name == name } }

    /// Every part named `name`, in order (for repeated fields such as multi-file inputs).
    public func all(_ name: String) -> [Part] { parts.filter { $0.name == name } }

    /// Parses a `multipart/form-data` body delimited by `boundary` (RFC 7578 §4 / RFC 2046 §5.1).
    ///
    /// Returns `nil` if the body has no valid opening or closing delimiter; a part missing a
    /// `Content-Disposition` `name` is skipped. Lenient and trap-free.
    public static func parse(_ body: [UInt8], boundary: String) -> Self? {
        let crlf: [UInt8] = [0x0D, 0x0A]
        let delimiter = crlf + Array("--\(boundary)".utf8)  // "\r\n--boundary"
        // Prepend CRLF so the opening "--boundary" matches the same delimiter as the inner ones.
        let data = crlf + body
        guard var range = firstRange(of: delimiter, in: data, from: 0) else {
            return nil
        }
        var parts: [Part] = []
        while true {
            let after = range.upperBound
            // A closing delimiter is "--boundary--": two dashes follow the boundary.
            if after + 1 < data.count, data[after] == 0x2D, data[after + 1] == 0x2D {
                return Self(parts: parts)
            }
            // Otherwise CRLF follows the boundary line; the part runs to the next delimiter.
            guard let lineEnd = firstRange(of: crlf, in: data, from: after)?.upperBound,
                let next = firstRange(of: delimiter, in: data, from: lineEnd)
            else {
                return nil  // no terminating delimiter — malformed
            }
            if let part = parsePart(Array(data[lineEnd ..< next.lowerBound])) {
                parts.append(part)
            }
            range = next
        }
    }

    /// The `boundary` parameter of a `multipart/form-data` `Content-Type` value (RFC 7578 §4.1), or nil.
    public static func boundary(ofContentType value: String) -> String? {
        parameter("boundary", in: value)
    }

    /// Parses one part's `header section CRLF CRLF body` into a ``Part`` (RFC 7578 §4.2); nil if it has
    /// no `Content-Disposition` `name`.
    private static func parsePart(_ content: [UInt8]) -> Part? {
        let blankLine: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        guard let headerEnd = firstRange(of: blankLine, in: content, from: 0) else {
            return nil
        }
        let headers = parseHeaders(Array(content[0 ..< headerEnd.lowerBound]))
        guard let disposition = headers["content-disposition"],
            let name = parameter("name", in: disposition)
        else {
            return nil
        }
        return Part(
            name: name,
            filename: parameter("filename", in: disposition),
            contentType: headers["content-type"],
            body: Array(content[headerEnd.upperBound...])
        )
    }

    /// Parses a part's header lines (`Name: value`, CRLF-separated) into lowercase-keyed pairs.
    private static func parseHeaders(_ bytes: [UInt8]) -> [String: String] {
        var headers: [String: String] = [:]
        // Split on the LF byte (then drop a trailing CR) rather than `String.split(separator:)`, which is
        // ambiguous for a "\n" literal and was silently not splitting CRLF-joined header lines.
        for lineBytes in bytes.split(separator: 0x0A, omittingEmptySubsequences: true) {
            let line = String(
                decoding: lineBytes.last == 0x0D ? lineBytes.dropLast() : lineBytes,
                as: Unicode.UTF8.self
            )
            guard let colon = line.firstIndex(of: ":") else {
                continue
            }
            let name = trimmed(line[..<colon]).lowercased()
            headers[name] = trimmed(line[line.index(after: colon)...])
        }
        return headers
    }

    /// The value of the `name=` parameter in a header value (e.g. `form-data; name="x"`), unquoted; nil
    /// if absent.
    private static func parameter(_ name: String, in value: String) -> String? {
        for segment in value.split(separator: ";") {
            let token = segment.drop { $0 == " " || $0 == "\t" }
            guard token.lowercased().hasPrefix("\(name)=") else {
                continue
            }
            var raw = token.dropFirst(name.count + 1)
            if raw.hasPrefix("\"") {
                raw = raw.dropFirst()
                if let close = raw.firstIndex(of: "\"") {
                    raw = raw[..<close]
                }
            }
            return String(raw)
        }
        return nil
    }

    /// `slice` with leading and trailing ASCII spaces/tabs removed.
    private static func trimmed(_ slice: Substring) -> String {
        let leading = slice.drop { $0 == " " || $0 == "\t" }
        var end = leading.endIndex
        while end > leading.startIndex {
            let prior = leading.index(before: end)
            guard leading[prior] == " " || leading[prior] == "\t" else {
                break
            }
            end = prior
        }
        return String(leading[..<end])
    }

    /// The first range of `needle` in `haystack` at or after `start`, or nil (a small substring search).
    private static func firstRange(
        of needle: [UInt8], in haystack: [UInt8], from start: Int
    ) -> Range<Int>? {
        guard !needle.isEmpty, haystack.count - start >= needle.count else {
            return nil
        }
        let last = haystack.count - needle.count
        var index = start
        while index <= last {
            var matched = 0
            while matched < needle.count, haystack[index + matched] == needle[matched] {
                matched += 1
            }
            if matched == needle.count {
                return index ..< (index + needle.count)
            }
            index += 1
        }
        return nil
    }
}
