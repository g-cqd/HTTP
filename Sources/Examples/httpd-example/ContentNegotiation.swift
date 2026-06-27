//
//  ContentNegotiation.swift
//  httpd-example
//
//  A proactive content-negotiation demo route (RFC 9110 §12.5): one resource served as JSON or HTML
//  per the client's `Accept`, with a greeting localized per `Accept-Language`. It exercises the
//  library's ``Accept`` / ``AcceptLanguage`` value types and their `bestMatch(among:)` selectors
//  (mirroring the `Accept-Encoding` q-value negotiation `CompressionMiddleware` already does).
//
//  The chosen dimensions are echoed in `Vary` (RFC 9110 §12.5.5) so a cache keys on them; the
//  field names are *appended* (not set) so they compose with the `Accept-Encoding` the downstream
//  `CompressionMiddleware` adds. An `Accept` that admits neither media type is `406 Not Acceptable`
//  (RFC 9110 §15.5.7); an absent `Accept` means "all media types acceptable" (§12.5.1), so it falls
//  back to JSON. Language never 406s: an absent or unmatched `Accept-Language` falls back to the
//  default (`en`), the conventional friendly posture (RFC 9110 §12.5.4).
//
//  Try:
//    curl -v -H 'Accept: text/html'                http://127.0.0.1:8080/negotiate
//    curl -v -H 'Accept: application/json'         http://127.0.0.1:8080/negotiate
//    curl -v -H 'Accept: text/html;q=0.9' -H 'Accept-Language: fr' http://127.0.0.1:8080/negotiate
//    curl -v -H 'Accept: image/png'               http://127.0.0.1:8080/negotiate   # 406
//

import HTTPCore
import HTTPServer

/// The `GET /negotiate` content-negotiation demo (RFC 9110 §12.5): one resource, JSON or HTML.
enum ContentNegotiation {
    /// The media types this resource can produce, in server-preference order (RFC 9110 §12.1).
    private static let mediaTypes = ["application/json", "text/html"]

    /// The languages the greeting comes in, in server-preference order; first is the default.
    private static let languages = ["en", "fr"]

    /// The route to register in the `Router { ... }` table; `RouteBuilder` lifts the result.
    static func route() -> Route {
        Route.get("/negotiate") { request, _, _ in
            // RFC 9110 §12.5.1: an absent `Accept` admits every media type, so fall back to the
            // default; a present `Accept` admitting neither candidate is `406` (§15.5.7).
            let mediaType: String
            if let accept = request.accept {
                guard let matched = accept.bestMatch(among: mediaTypes) else {
                    return notAcceptable()
                }
                mediaType = matched
            }
            else {
                mediaType = defaultMediaType
            }
            // Language never 406s: an absent or unmatched `Accept-Language` falls back to `en`.
            let language = request.acceptLanguage?.bestMatch(among: languages) ?? defaultLanguage
            return represent(mediaType: mediaType, language: language)
        }
    }

    /// The default media type when the client sends no `Accept` (RFC 9110 §12.5.1).
    private static var defaultMediaType: String {
        mediaTypes.first ?? "application/json"
    }

    /// The default language when the client sends no usable `Accept-Language` (RFC 9110 §12.5.4).
    private static var defaultLanguage: String {
        languages.first ?? "en"
    }

    /// Renders the resource in `mediaType`, localizing the greeting to `language`.
    ///
    /// Both negotiated dimensions are recorded in `Vary` (RFC 9110 §12.5.5) so a cache keys on it.
    /// (`Content-Language`, RFC 9110 §8.5.1, is intentionally omitted: it is not a registered
    /// ``HTTPFieldName`` constant here, and the chosen language is already carried in the HTML
    /// `lang` attribute and the JSON body, keeping the demo to the registered field set.)
    private static func represent(mediaType: String, language: String) -> ServerResponse {
        let greeting = greeting(for: language)
        let response =
            mediaType == "text/html"
            ? html(greeting: greeting, language: language)
            : json(greeting: greeting, language: language)
        return varying(response)
    }

    /// The greeting for `language`, falling back to English for any unexpected value.
    private static func greeting(for language: String) -> String {
        switch language {
            case "fr":
                "Bonjour"
            default:
                "Hello"
        }
    }

    /// A JSON representation of the resource (RFC 8259); hand-built to stay Foundation-free.
    private static func json(greeting: String, language: String) -> ServerResponse {
        let body = """
            {"greeting":"\(greeting)","language":"\(language)"}

            """
        return .json(Array(body.utf8))
    }

    /// An HTML representation of the resource, tagging the document language for assistive tech.
    private static func html(greeting: String, language: String) -> ServerResponse {
        let body = """
            <!doctype html>
            <html lang="\(language)">
            <head><meta charset="utf-8"><title>\(greeting)</title></head>
            <body><h1>\(greeting)</h1></body>
            </html>

            """
        var fields = HTTPFields()
        _ = fields.setValue("text/html; charset=utf-8", for: .contentType)
        let head = HTTPResponse(status: .ok, headerFields: fields)
        return ServerResponse(head, body: Array(body.utf8))
    }

    /// Adds the `Vary` dimensions this resource negotiates on (RFC 9110 §12.5.5).
    ///
    /// `Vary` is *appended*, not set, so the field names compose with the `Accept-Encoding` the
    /// downstream `CompressionMiddleware` adds rather than clobbering it.
    private static func varying(_ response: ServerResponse) -> ServerResponse {
        var response = response
        _ = response.head.headerFields.append("Accept", for: .vary)
        _ = response.head.headerFields.append("Accept-Language", for: .vary)
        return response
    }

    /// A `406 Not Acceptable` (RFC 9110 §15.5.7): the `Accept` admits neither representation.
    ///
    /// `406` is a constant in `100...599`, so `HTTPStatus(code:)` never returns nil here; the
    /// `?? .badRequest` only satisfies the project's no-force-unwrap rule.
    private static func notAcceptable() -> ServerResponse {
        let status = HTTPStatus(code: 406) ?? .badRequest
        let offered = mediaTypes.joined(separator: " or ")
        let body = "Not Acceptable: this resource is available as \(offered).\n"
        var response = ServerResponse.text(body, status: status)
        _ = response.head.headerFields.append("Accept", for: .vary)
        return response
    }
}
