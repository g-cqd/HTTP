//
//  AccessLogMiddleware.swift
//  HTTPServer
//
//  A side-effecting, pass-through middleware: it records one access-log line per exchange and returns
//  the response untouched. The log sink is injected, so it stays testable and never assumes a logging
//  backend.
//
//  The line is built from the request target, which is entirely attacker-controlled, so two things are
//  neutralized before it is written. The query is dropped by default (CWE-532, insertion of sensitive
//  information into a log file): query parameters routinely carry bearer tokens — RFC 6750 §2.3 warns
//  against putting them there precisely because "URIs are often recorded ... in various logs" —
//  password-reset nonces, OAuth authorization codes (RFC 6749 §4.1.2), pre-signed URL signatures, and
//  personal data. Including the query is an explicit opt-in, and even then every value is redacted
//  unless it is named in an allow-list. Any control character left in the target is percent-escaped, so
//  a raw LF in a path cannot forge a second log line (CWE-117, improper output neutralization for logs).
//

public import HTTPCore

/// Records one access-log line per request — `METHOD path -> status` — through an injected sink.
public struct AccessLogMiddleware: HTTPMiddleware {
    /// What the log line keeps of the request target's query string.
    ///
    /// The default is ``omitted``: a query is far more likely to hold a credential than to hold
    /// something worth logging, and a log file is the wrong place to find out which (CWE-532).
    public enum QueryPolicy: Sendable, Equatable {
        /// The query is dropped entirely — only the path is logged. The default.
        case omitted
        /// Parameter names are kept, every value is replaced by `REDACTED`.
        ///
        /// The names are usually the diagnostic signal ("was `page` even sent?"); the values are the
        /// secret.
        case redacted
        /// The values of the named parameters are logged verbatim; every other value is redacted.
        ///
        /// Names are matched as they appear on the wire, before percent-decoding: a client sending
        /// `%74oken` therefore misses the allow-list and gets *more* redaction, never less.
        case allowing(Set<String>)
    }

    /// The placeholder written in place of a query value that is not allow-listed.
    private static let placeholder = "REDACTED"

    private let sink: @Sendable (String) -> Void
    private let query: QueryPolicy

    /// Creates the middleware, sending each formatted line to `sink` (e.g. `{ print($0) }`).
    ///
    /// `query` defaults to ``QueryPolicy/omitted``, so a target's query never reaches the sink unless
    /// the caller asks for it.
    public init(
        query: QueryPolicy = .omitted,
        _ sink: @escaping @Sendable (String) -> Void
    ) {
        self.sink = sink
        self.query = query
    }

    /// Delegates, then logs the method, normalized target, and resulting status.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        let response = await next.respond(to: request, body: body, context: context)
        let target = Self.target(request.path, query: query)
        sink("\(request.method.rawValue) \(target) -> \(response.head.status.code)")
        return response
    }

    /// The loggable form of `path`: the path itself, plus as much of the query as `query` permits.
    ///
    /// A fragment is dropped unconditionally — RFC 9112 §3.2 has no fragment in a request target, so
    /// one that arrives anyway is junk with no diagnostic value.
    static func target(_ path: String, query: QueryPolicy) -> String {
        let withoutFragment = path.prefix { $0 != "#" }
        guard let mark = withoutFragment.firstIndex(of: "?") else {
            return neutralized(withoutFragment)
        }
        let head = neutralized(withoutFragment[..<mark])
        guard query != .omitted else {
            return head
        }
        let rawQuery = withoutFragment[withoutFragment.index(after: mark)...]
        return head + "?" + parameters(rawQuery, query)
    }

    /// `rawQuery` with every value not permitted by `query` replaced by the placeholder.
    private static func parameters(_ rawQuery: Substring, _ query: QueryPolicy) -> String {
        var out = ""
        out.reserveCapacity(rawQuery.count)
        for element in rawQuery.split(separator: "&", omittingEmptySubsequences: false) {
            if !out.isEmpty {
                out += "&"
            }
            guard let equals = element.firstIndex(of: "=") else {
                out += neutralized(element)  // a valueless parameter has no value to leak
                continue
            }
            let name = element[..<equals]
            let raw = element[element.index(after: equals)...]
            out += neutralized(name) + "=" + value(raw, named: name, query)
        }
        return out
    }

    /// `raw` verbatim when `name` is allow-listed, else the placeholder.
    private static func value(
        _ raw: Substring,
        named name: Substring,
        _ query: QueryPolicy
    ) -> String {
        guard case .allowing(let permitted) = query, permitted.contains(String(name)) else {
            return placeholder
        }
        return neutralized(raw)
    }

    /// `text` with every C0 control, SP, and DEL percent-escaped (CWE-117).
    ///
    /// A raw LF or CR in a logged target would end the line and let what follows pose as a fresh
    /// entry; a NUL would truncate the record for a C-string consumer; a SP would blur the
    /// `METHOD target -> status` framing. Escaping rather than stripping keeps the log honest about
    /// what was actually received.
    private static func neutralized(_ text: Substring) -> String {
        guard text.unicodeScalars.contains(where: isUnsafe) else {
            return String(text)  // the overwhelmingly common case: nothing to rewrite
        }
        var out = ""
        out.reserveCapacity(text.unicodeScalars.count)
        for scalar in text.unicodeScalars {
            guard isUnsafe(scalar) else {
                out.unicodeScalars.append(scalar)
                continue
            }
            let hex = String(scalar.value, radix: 16, uppercase: true)
            out += hex.count == 1 ? "%0" + hex : "%" + hex
        }
        return out
    }

    /// Whether `scalar` must not appear raw in a log line: a C0 control, SP, or DEL.
    private static func isUnsafe(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < 0x21 || scalar.value == 0x7F
    }
}
