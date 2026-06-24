//
//  HTTPFields+ContentLength.swift
//  HTTPCore
//
//  RFC 9110 §8.6 — Content-Length, with the RFC 9112 §6.3 anti-smuggling rules.
//

extension HTTPFields {
    /// The result of interpreting the `Content-Length` field(s) of a message (RFC 9110 §8.6).
    public enum ContentLength: Sendable, Equatable {
        /// No `Content-Length` field is present.
        case absent
        /// A `Content-Length` is present but malformed or self-contradictory and MUST be rejected
        /// as an unrecoverable framing error (RFC 9112 §6.3) — a request-smuggling vector.
        case invalid
        /// A single, well-formed, non-negative length.
        case length(Int)
    }

    /// Interprets the message's `Content-Length` field(s) per RFC 9110 §8.6 and RFC 9112 §6.3.
    ///
    /// Returns ``ContentLength/invalid`` when any value is not a non-negative decimal integer, or
    /// when multiple values disagree (including a comma-combined list produced by HTTP/2→HTTP/1.1
    /// down-conversion). Multiple *identical* valid values collapse to that length.
    public var contentLength: ContentLength {
        var resolved: Int?
        var present = false
        // Iterate the fields directly — no intermediate `[String]` from `values(for:)`.
        for field in self where field.name == .contentLength {
            present = true
            let utf8 = field.value.utf8
            var start = utf8.startIndex
            // A value may itself be a comma list (e.g. "5, 5") after HTTP/2 → HTTP/1.1 coalescing.
            // Tokenize on commas with index slicing (Substring views) — no `[Substring]` from `split`.
            while true {
                let comma = utf8[start...].firstIndex(of: 0x2C)  // ","
                let token = utf8[start ..< (comma ?? utf8.endIndex)]
                guard let parsed = Self.parseContentLengthToken(token) else {
                    return .invalid
                }
                if let resolvedValue = resolved, resolvedValue != parsed {
                    return .invalid
                }
                resolved = parsed
                guard let comma else { break }
                start = utf8.index(after: comma)
            }
        }
        guard present else {
            return .absent
        }
        guard let resolved else {
            return .invalid
        }
        return .length(resolved)
    }

    /// Parses one `Content-Length` token: optional surrounding OWS around `1*DIGIT` (RFC 9110 §8.6).
    ///
    /// Returns `nil` for an empty token, any non-digit byte, a sign, or a value that overflows `Int`.
    private static func parseContentLengthToken(_ utf8: Substring.UTF8View) -> Int? {
        var index = utf8.startIndex
        var tail = utf8.endIndex

        // Trim leading / trailing OWS (SP / HTAB) — RFC 9110 §5.6.3.
        while index < tail, utf8[index] == 0x20 || utf8[index] == 0x09 {
            index = utf8.index(after: index)
        }
        while tail > index {
            let previous = utf8.index(before: tail)
            guard utf8[previous] == 0x20 || utf8[previous] == 0x09 else { break }
            tail = previous
        }
        guard index < tail else {
            return nil  // empty after trimming
        }

        var result = 0
        var cursor = index
        while cursor < tail {
            let byte = utf8[cursor]
            guard byte >= 0x30, byte <= 0x39 else {
                return nil  // not a DIGIT
            }
            let (scaled, scaleOverflow) = result.multipliedReportingOverflow(by: 10)
            guard !scaleOverflow else {
                return nil
            }
            let (sum, addOverflow) = scaled.addingReportingOverflow(Int(byte - 0x30))
            guard !addOverflow else {
                return nil
            }
            result = sum
            cursor = utf8.index(after: cursor)
        }
        return result
    }
}
