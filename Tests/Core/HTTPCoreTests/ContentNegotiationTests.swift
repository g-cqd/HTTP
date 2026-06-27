//
//  ContentNegotiationTests.swift
//  HTTPCoreTests
//
//  RFC 9110 §12.5 proactive content negotiation: Accept (§12.5.1) media-range selection with q-values,
//  specificity override, and wildcards; Accept-Language (§12.5.4 / RFC 4647 §3.3.1) basic filtering;
//  q=0 exclusion, no-acceptable-match, server-preference tie-breaking, lenient parsing, and the
//  HTTPRequest.accept / .acceptLanguage accessors.
//

import HTTPCore
import Testing

@Suite("RFC 9110 §12.5 content negotiation")
struct ContentNegotiationTests {
    // MARK: - Accept (§12.5.1)

    @Test("higher q wins; absent q defaults to 1.0")
    func acceptQualityPreference() {
        let accept = Accept(field: "application/json;q=0.9, text/html")
        #expect(accept.bestMatch(among: ["application/json", "text/html"]) == "text/html")
        #expect(accept.bestMatch(among: ["application/json"]) == "application/json")
    }

    @Test("a more specific range overrides a broader one (§12.5.1)")
    func acceptSpecificityOverride() {
        let accept = Accept(field: "text/*;q=0.5, text/html;q=1.0")
        // text/html takes the exact range (1.0); text/plain only the text/* range (0.5, still > 0).
        #expect(accept.bestMatch(among: ["text/plain", "text/html"]) == "text/html")
        #expect(accept.bestMatch(among: ["text/plain"]) == "text/plain")
    }

    @Test("*/* matches anything; ties break by server-preference order (§12.1)")
    func acceptWildcardAndTieBreak() {
        let accept = Accept(field: "*/*")
        #expect(accept.bestMatch(among: ["application/json", "text/html"]) == "application/json")
        #expect(accept.bestMatch(among: ["text/html", "application/json"]) == "text/html")
    }

    @Test("q=0 refuses a type; no acceptable candidate yields nil (→ 406)")
    func acceptRefusalAndNoMatch() {
        let refused = Accept(field: "text/html;q=0, application/json")
        #expect(refused.bestMatch(among: ["text/html", "application/json"]) == "application/json")
        // Only the refused type is on offer → nothing acceptable.
        #expect(refused.bestMatch(among: ["text/html"]) == nil)

        let unmatched = Accept(field: "application/xml")
        #expect(unmatched.bestMatch(among: ["application/json", "text/html"]) == nil)
    }

    @Test("parsing is lenient: a malformed element is skipped, not fatal")
    func acceptLenientParsing() {
        // "@@@" is junk (no crash); "text/html;q=bogus" → q defaults to 1.0 (unparseable weight), so
        // both real types stay acceptable at full quality.
        let accept = Accept(field: "@@@, text/html;q=bogus, application/json")
        #expect(accept.bestMatch(among: ["text/html"]) == "text/html")
        #expect(accept.bestMatch(among: ["application/json"]) == "application/json")
        // An empty field parses to no ranges, so nothing matches.
        #expect(Accept(field: "").bestMatch(among: ["text/html"]) == nil)
    }

    // MARK: - Accept-Language (§12.5.4 / RFC 4647 basic filtering)

    @Test("higher q wins across language tags")
    func languageQualityPreference() {
        let language = AcceptLanguage(field: "en-US, fr;q=0.8")
        #expect(language.bestMatch(among: ["fr", "en-US"]) == "en-US")
    }

    @Test("a range matches a tag by prefix on a subtag boundary (RFC 4647 §3.3.1)")
    func languagePrefixMatch() {
        let language = AcceptLanguage(field: "en;q=0.9")
        #expect(language.bestMatch(among: ["en-US"]) == "en-US")  // en matches en-US
        #expect(language.bestMatch(among: ["fr"]) == nil)  // en does not match fr
    }

    @Test("the longest (most specific) matching range supplies the weight")
    func languageSpecificity() {
        let language = AcceptLanguage(field: "en;q=0.5, en-US;q=0.9")
        #expect(language.bestMatch(among: ["en-US"]) == "en-US")  // exact en-US range (0.9)
        // en-GB matches only the broader `en` range (0.5) — still acceptable.
        #expect(language.bestMatch(among: ["en-GB"]) == "en-GB")
    }

    @Test("* matches any tag; q=0 refuses; no match yields nil")
    func languageWildcardRefusalAndNoMatch() {
        #expect(AcceptLanguage(field: "*").bestMatch(among: ["de"]) == "de")
        #expect(AcceptLanguage(field: "en;q=0").bestMatch(among: ["en-US"]) == nil)
        #expect(AcceptLanguage(field: "fr").bestMatch(among: ["en", "de"]) == nil)
    }

    // MARK: - HTTPRequest accessors

    @Test("HTTPRequest.accept / .acceptLanguage read the field, nil when absent")
    func requestAccessors() {
        var fields = HTTPFields()
        _ = fields.append("text/html, application/json;q=0.9", for: .accept)
        _ = fields.append("en-US, en;q=0.8", for: .acceptLanguage)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        #expect(request.accept?.bestMatch(among: ["application/json", "text/html"]) == "text/html")
        #expect(request.acceptLanguage?.bestMatch(among: ["en", "fr"]) == "en")

        let bare = HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
        #expect(bare.accept == nil)
        #expect(bare.acceptLanguage == nil)
    }
}
