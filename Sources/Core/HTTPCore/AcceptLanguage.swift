//
//  AcceptLanguage.swift
//  HTTPCore
//
//  RFC 9110 §12.5.4 — the `Accept-Language` request header, parsed into weighted language ranges with a
//  `bestMatch(among:)` selector using RFC 4647 §3.3.1 basic filtering. A reusable value type alongside
//  ``Accept`` / ``HTTPPriority``. Lenient + trap-free; no Foundation.
//

/// A parsed `Accept-Language` header (RFC 9110 §12.5.4): the client's weighted language-range preferences.
public struct AcceptLanguage: Sendable, Equatable {
    /// A single language range with its quality weight — e.g. `en-US;q=0.8`, `fr`, or `*`.
    public struct LanguageRange: Sendable, Equatable {
        /// The lowercased language range (RFC 4647), e.g. `en`, `en-us`, or `*`.
        public let range: String
        /// The quality weight in 0...1 (RFC 9110 §12.4.2); `q=0` means "not acceptable".
        public let quality: Double

        /// Whether this range matches `tag` by RFC 4647 §3.3.1 basic filtering: `*` matches all, else an
        /// exact match or a prefix on a subtag boundary (`en` matches `en-US`). `tag` must be lowercased.
        func matches(tag: String) -> Bool {
            range == "*" || tag == range || tag.hasPrefix(range + "-")
        }
    }

    /// The language ranges, in the order received.
    public let ranges: [LanguageRange]

    /// Parses an `Accept-Language` field value (RFC 9110 §12.5.4); an unparseable element is skipped.
    public init(field value: String) {
        ranges = AcceptParsing.elements(value)
            .map { LanguageRange(range: $0.token, quality: $0.quality) }
    }

    /// The most acceptable language tag in `available` (server-preference order), or `nil` when the
    /// client accepts none of them.
    ///
    /// Each candidate's weight is the `q` of the *longest* (most specific) matching range; the
    /// highest-weighted candidate wins, ties broken by `available` order.
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

    /// The weight the client assigns `tag` — the `q` of its longest matching range (`*` is least
    /// specific), or `nil` when no range matches.
    private func effectiveQuality(for tag: String) -> Double? {
        let lowered = tag.lowercased()
        var chosen: (quality: Double, length: Int)?
        for range in ranges where range.matches(tag: lowered) {
            let length = range.range == "*" ? 0 : range.range.count
            if length > (chosen?.length ?? -1) {
                chosen = (range.quality, length)
            }
        }
        return chosen?.quality
    }
}

extension HTTPRequest {
    /// The request's parsed `Accept-Language` header (RFC 9110 §12.5.4), or `nil` when none is present.
    public var acceptLanguage: AcceptLanguage? {
        guard let value = headerFields[.acceptLanguage] else {
            return nil
        }
        return AcceptLanguage(field: value)
    }
}
