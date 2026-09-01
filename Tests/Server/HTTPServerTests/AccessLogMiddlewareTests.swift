//
//  AccessLogMiddlewareTests.swift
//  HTTPServerTests
//
//  CWE-532 (insertion of sensitive information into a log file) — a request target's query routinely
//  carries bearer tokens (RFC 6750 §2.3 warns against exactly this), password-reset nonces, signed S3
//  URLs, and personal data. The access log must therefore drop the query by default and redact values
//  even when an operator opts in. CWE-117 (improper output neutralization for logs) — a target is
//  attacker-controlled, so a control character in it must not be able to forge a second log line.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("AccessLogMiddleware — query redaction (CWE-532)")
struct AccessLogMiddlewareTests {
    private let ok = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }

    private func request(_ path: String) -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "x", path: path)
    }

    /// The single line `AccessLogMiddleware` emits for `path` under `query`.
    private func line(
        _ path: String,
        query: AccessLogMiddleware.QueryPolicy = .omitted
    ) async -> String {
        let sink = Recorder()
        let responder = ok.wrapped(by: AccessLogMiddleware(query: query) { sink.add($0) })
        _ = await responder.respond(to: request(path), body: [])
        return sink.entries.first ?? ""
    }

    @Test(
        "a secret in the query never reaches the log by default",
        arguments: [
            "/x?token=secret",
            "/x?a=1&token=secret",
            "/reset?nonce=secret&user=bob",
            "/x?token=secret#frag",
            "/x?TOKEN=secret",
            "/oauth/callback?code=secret&state=xyz"
        ]
    )
    func queryOmittedByDefault(_ path: String) async {
        let logged = await line(path)
        #expect(!logged.contains("secret"), "the log line leaked a query value: \(logged)")
        #expect(!logged.contains("?"))
    }

    @Test("the path itself is still logged, unchanged")
    func pathSurvives() async {
        #expect(await line("/health") == "GET /health -> 200")
        #expect(await line("/x?token=secret") == "GET /x -> 200")
        #expect(await line("/") == "GET / -> 200")
        #expect(await line("") == "GET  -> 200")
    }

    @Test("opting into the query redacts every value, keeping the parameter names")
    func redactedOptIn() async {
        let logged = await line("/x?token=secret&page=2", query: .redacted)
        #expect(!logged.contains("secret"))
        #expect(logged == "GET /x?token=REDACTED&page=REDACTED -> 200")
    }

    @Test("a valueless query parameter has nothing to redact and is kept")
    func valuelessParameter() async {
        let logged = await line("/x?debug&token=t", query: .redacted)
        #expect(logged == "GET /x?debug&token=REDACTED -> 200")
    }

    @Test("an allow-list keeps only the named values in the clear")
    func allowList() async {
        let logged = await line("/x?page=2&token=secret", query: .allowing(["page"]))
        #expect(!logged.contains("secret"))
        #expect(logged == "GET /x?page=2&token=REDACTED -> 200")
    }

    @Test(
        "a control character in the target cannot forge a log line (CWE-117)",
        arguments: ["/a\nGET /forged", "/a\rb", "/a\u{7F}b", "/a\u{0}b"]
    )
    func controlCharactersNeutralized(_ path: String) async {
        let logged = await line(path, query: .redacted)
        #expect(!logged.contains("\n"))
        #expect(!logged.contains("\r"))
        #expect(!logged.contains("\u{7F}"))
        #expect(!logged.contains("\u{0}"))
    }

    @Test("a redacted parameter name is neutralized too, not just the path")
    func controlCharacterInParameterName() async {
        let logged = await line("/x?a\rb=1", query: .redacted)
        #expect(!logged.contains("\r"))
        #expect(logged == "GET /x?a%0Db=REDACTED -> 200")
    }
}
