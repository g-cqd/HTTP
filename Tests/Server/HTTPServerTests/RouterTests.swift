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
            Route.get("/users/:id") { _, _, context in Self.ok(context.parameters["id"] ?? "?") }
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

    @Test("HEAD is served by the matching GET route, not 405 (RFC 9110 §9.3.2)")
    func headFoldsToGet() async {
        let router = Router { Route.get("/a") { _, _, _ in Self.ok("a") } }
        // HEAD matches the GET route; the server omits the body downstream (the router returns it).
        let response = await router.respond(to: request(.head, "/a"), body: [])
        #expect(response.head.status == .ok)
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
            Route.get("/users/:id") { _, _, context in
                Self.ok("param:\(context.parameters["id"] ?? "")")
            }
            Route.get("/users/me") { _, _, _ in Self.ok("me") }
        }
        // "/users/me" matches the :id route first (declaration order), capturing id = "me".
        let response = await router.respond(to: request(.get, "/users/me"), body: [])
        #expect(response.body == Array("param:me".utf8))
    }

    @Test("a route group prefixes child paths and scopes its middleware to the subtree")
    func routeGroup() async {
        let router = Router {
            Route.get("/open") { _, _, _ in Self.ok("open") }
            RouteGroup("/api", middleware: [ServerHeaderMiddleware("grouped")]) {
                Route.get("/ping") { _, _, _ in Self.ok("pong") }
            }
        }
        // The child path is prefixed, and the group middleware ran (Server stamped) inside the group.
        let grouped = await router.respond(to: request(.get, "/api/ping"), body: [])
        #expect(grouped.body == Array("pong".utf8))
        #expect(grouped.head.headerFields[.server] == "grouped")
        // The middleware did not run outside the group...
        let open = await router.respond(to: request(.get, "/open"), body: [])
        #expect(open.head.headerFields[.server] == nil)
        // ...and the un-prefixed child path does not match.
        let bare = await router.respond(to: request(.get, "/ping"), body: [])
        #expect(bare.head.status == .notFound)
    }

    @Test("a parameter route inside a middleware group still receives its captured parameter (#9)")
    func groupedParameterRoute() async {
        // The route carries group middleware, so its handler runs through the precomputed chain with
        // parameters carried on the context (audit #9) — the handler must still see `:id`, and the
        // group middleware must still run.
        let router = Router {
            RouteGroup("/api", middleware: [ServerHeaderMiddleware("grouped")]) {
                Route.get("/users/:id") { _, _, context in
                    Self.ok(context.parameters["id"] ?? "?")
                }
            }
        }
        let response = await router.respond(to: request(.get, "/api/users/42"), body: [])
        #expect(response.body == Array("42".utf8))  // the captured parameter reached the handler
        #expect(response.head.headerFields[.server] == "grouped")  // group middleware still ran
    }

    @Test("nested groups compose their prefixes")
    func nestedGroups() async {
        let router = Router {
            RouteGroup("/api") {
                RouteGroup("/v1") {
                    Route.get("/health") { _, _, _ in Self.ok("ok") }
                }
            }
        }
        let response = await router.respond(to: request(.get, "/api/v1/health"), body: [])
        #expect(response.head.status == .ok)
    }

    @Test("a trailing catch-all captures the remaining path (RFC 3986 §3.3)")
    func catchAll() async {
        let router = Router {
            Route.get("/files/*path") { _, _, context in Self.ok(context.parameters["path"] ?? "") }
        }
        let response = await router.respond(to: request(.get, "/files/css/site.css"), body: [])
        #expect(response.body == Array("css/site.css".utf8))
    }

    @Test("an unnamed catch-all captures under \"*\"")
    func unnamedCatchAll() async {
        let router = Router {
            Route.get("/assets/*") { _, _, context in Self.ok(context.parameters["*"] ?? "") }
        }
        let response = await router.respond(to: request(.get, "/assets/a/b"), body: [])
        #expect(response.body == Array("a/b".utf8))
    }

    @Test("OPTIONS to a known path is auto-answered with 204 + Allow (RFC 9110 §9.3.7)")
    func optionsAutoResponds() async {
        let router = Router {
            Route.get("/a") { _, _, _ in Self.ok("a") }
            Route.post("/a") { _, _, _ in Self.ok("a") }
        }
        let response = await router.respond(to: request(.options, "/a"), body: [])
        #expect(response.head.status == .noContent)
        #expect(response.head.headerFields[.allow] == "GET, HEAD, POST, OPTIONS")
    }

    @Test("405 carries an Allow header listing the path's methods (RFC 9110 §15.5.6)")
    func methodNotAllowedAllow() async {
        let router = Router { Route.get("/a") { _, _, _ in Self.ok("a") } }
        let response = await router.respond(to: request(.delete, "/a"), body: [])
        #expect(response.head.status == .methodNotAllowed)
        #expect(response.head.headerFields[.allow] == "GET, HEAD, OPTIONS")
    }

    @Test("an explicit OPTIONS route overrides the automatic response")
    func explicitOptionsWins() async {
        let router = Router {
            Route.get("/a") { _, _, _ in Self.ok("a") }
            Route.options("/a") { _, _, _ in Self.ok("custom") }
        }
        let response = await router.respond(to: request(.options, "/a"), body: [])
        #expect(response.body == Array("custom".utf8))
    }

    @Test("OPTIONS * reports the server-wide method set (RFC 9110 §9.3.7)")
    func optionsAsterisk() async {
        let router = Router {
            Route.get("/a") { _, _, _ in Self.ok("a") }
            Route.post("/b") { _, _, _ in Self.ok("b") }
        }
        let response = await router.respond(to: request(.options, "*"), body: [])
        #expect(response.head.status == .noContent)
        #expect(response.head.headerFields[.allow] == "GET, HEAD, POST, OPTIONS")
    }

    @Test("dynamic-member access reads a captured parameter")
    func parameterDynamicMember() async {
        let router = Router {
            Route.get("/users/:id") { _, _, context in Self.ok(context.parameters.id ?? "?") }
        }
        let response = await router.respond(to: request(.get, "/users/7"), body: [])
        #expect(response.body == Array("7".utf8))
    }
}
