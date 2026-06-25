//
//  RouterTests.swift
//  HTTPServerTests
//
//  RFC 9110 — the result-builder routing DSL: static + parameterized matching, 404 / 405, path
//  normalization (trailing slash + query), and builder control flow (`for` / `if`).
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Routing — result-builder DSL")
struct RouterTests {
    private static func ok(_ text: String) -> ServerResponse {
        ServerResponse(HTTPResponse(status: .ok), body: Array(text.utf8))
    }

    private func request(_ method: HTTPMethod, _ path: String) -> HTTPRequest {
        HTTPRequest(method: method, scheme: "https", authority: "x", path: path)
    }

    @Test("matches a static route and runs its handler")
    func matchesStatic() async {
        let router = Router {
            Route.get("/health") { _, _, _ in Self.ok("ok") }
        }
        let response = await router.respond(to: request(.get, "/health"), body: [])
        #expect(response.head.status == .ok)
        #expect(response.body == Array("ok".utf8))
    }

    @Test("captures a :path parameter into RouteParameters")
    func capturesParameter() async {
        let router = Router {
            Route.get("/users/:id") { _, parameters, _ in Self.ok(parameters["id"] ?? "?") }
        }
        let response = await router.respond(to: request(.get, "/users/42"), body: [])
        #expect(response.body == Array("42".utf8))
    }

    @Test("an unmatched path is 404 Not Found (RFC 9110 §15.5.5)")
    func notFound() async {
        let router = Router { Route.get("/a") { _, _, _ in Self.ok("a") } }
        #expect(await router.respond(to: request(.get, "/b"), body: []).head.status == .notFound)
    }

    @Test("a known path with the wrong method is 405 Method Not Allowed (RFC 9110 §15.5.6)")
    func methodNotAllowed() async {
        let router = Router { Route.get("/a") { _, _, _ in Self.ok("a") } }
        let response = await router.respond(to: request(.post, "/a"), body: [])
        #expect(response.head.status == .methodNotAllowed)
    }

    @Test("a trailing slash and a query string do not affect matching (RFC 3986)")
    func normalizesPath() async {
        let router = Router { Route.get("/a/b") { _, _, _ in Self.ok("hit") } }
        #expect(await router.respond(to: request(.get, "/a/b/?q=1"), body: []).head.status == .ok)
    }

    @Test("the builder supports for-loops and conditionals")
    func builderControlFlow() async {
        let enableAdmin = true
        let router = Router {
            for name in ["x", "y"] {
                Route.get("/\(name)") { _, _, _ in Self.ok(name) }
            }
            if enableAdmin {
                Route.get("/admin") { _, _, _ in Self.ok("admin") }
            }
        }
        #expect(await router.respond(to: request(.get, "/y"), body: []).head.status == .ok)
        #expect(await router.respond(to: request(.get, "/admin"), body: []).head.status == .ok)
    }

    @Test("the first matching route wins")
    func firstMatchWins() async {
        let router = Router {
            Route.get("/users/:id") { _, parameters, _ in Self.ok("param:\(parameters["id"] ?? "")")
            }
            Route.get("/users/me") { _, _, _ in Self.ok("me") }
        }
        // "/users/me" matches the :id route first (declaration order), capturing id = "me".
        let response = await router.respond(to: request(.get, "/users/me"), body: [])
        #expect(response.body == Array("param:me".utf8))
    }
}
