//
//  Accept.swift
//  HTTPCore
//
//  RFC 9110 §12.5.1 — the `Accept` request header, parsed into weighted media ranges with a
//  `bestMatch(among:)` selector a handler uses to pick the representation it serves. Mirrors the
//  `Accept-Encoding` q-value negotiation `CompressionMiddleware` already does, as a reusable value type
//  (alongside ``HTTPPriority`` / ``QueryParameters``). Lenient + trap-free; no Foundation.
//

/// A parsed `Accept` header (RFC 9110 §12.5.1): the client's weighted media-range preferences.
public struct Accept: Sendable, Equatable {
    /// A single media range with its quality weight — e.g. `text/html;q=0.9`, `text/*`, or `*/*`.
    public struct MediaRange: Sendable, Equatable {
        /// The lowercased top-level type, or `*` for any.
        public let type: String
        /// The lowercased subtype, or `*` for any.
        public let subtype: String
        /// The quality weight in 0...1 (RFC 9110 §12.4.2); `q=0` means "not acceptable".
        public let quality: Double

        /// How specifically this range matches `type`/`subtype`: 2 = exact, 1 = `type/*`, 0 = `*/*`;
        /// `nil` if it does not match (RFC 9110 §12.5.1 — a more specific range overrides a broader one).
        func matchSpecificity(type: String, subtype: String) -> Int? {
            if self.type == "*" {
                return 0
            }
            guard self.type == type else {
                return nil
            }
            if self.subtype == "*" {
                return 1
            }
            return self.subtype == subtype ? 2 : nil
        }
    }

    /// The media ranges, in the order received.
    public let ranges: [MediaRange]

    /// Parses an `Accept` field value (RFC 9110 §12.5.1); an unparseable element is skipped.
    public init(field value: String) {
        ranges = AcceptParsing.elements(value)
            .map { element in
                let (type, subtype) = Self.splitMediaType(element.token)
                return MediaRange(type: type, subtype: subtype, quality: element.quality)
            }
    }

    /// The most acceptable media type in `available` (given in server-preference order), or `nil` when
    /// the client accepts none of them — every candidate is unmatched or `q=0`, so an origin may answer
    /// `406 Not Acceptable` (RFC 9110 §15.5.7) or fall back to a default.
    ///
    /// Each candidate's weight is the `q` of the *most specific* matching range (RFC 9110 §12.5.1); the
    /// highest-weighted candidate wins, ties broken by `available` order (server preference, §12.1).
    public func bestMatch(among available: [String]) -> String? {
        var best: (value: String, quality: Double)?
        for candidate in available {
            guard let quality = effectiveQuality(for: candidate), quality > 0 else {
                continue
            }
            if quality > (best?.quality ?? 0) {
                best = (candidate, quality)
            }
        }
        return best?.value
    }

    /// The weight the client assigns `mediaType` — the `q` of its most specific matching range, or
    /// `nil` when no range matches.
    private func effectiveQuality(for mediaType: String) -> Double? {
        let (type, subtype) = Self.splitMediaType(mediaType.lowercased())
        var chosen: (quality: Double, specificity: Int)?
        for range in ranges {
            guard let specificity = range.matchSpecificity(type: type, subtype: subtype) else {
                continue
            }
            if specificity > (chosen?.specificity ?? -1) {
                chosen = (range.quality, specificity)
            }
        }
        return chosen?.quality
    }

    /// Splits `value` (already lowercased) into a media `type`/`subtype` at the first `/`.
    private static func splitMediaType(_ value: String) -> (type: String, subtype: String) {
        guard let slash = value.firstIndex(of: "/") else {
            return (value, "")
        }
        return (String(value[..<slash]), String(value[value.index(after: slash)...]))
    }
}

extension HTTPRequest {
    /// The request's parsed `Accept` header (RFC 9110 §12.5.1), or `nil` when none is present.
    public var accept: Accept? {
        guard let value = headerFields[.accept] else {
            return nil
        }
        return Accept(field: value)
    }
}
