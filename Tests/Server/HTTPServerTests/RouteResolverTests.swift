//
//  RouteResolverTests.swift
//  HTTPServerTests
//
//  The head-time route-matching seam (Phase 1 foundation): ``Router`` matches a route's body limit,
//  WebSocket handler, and streaming opt-in from a request head (no handler run), and a ``MiddlewareChain``
//  or `wrapped(by:)` chain forwards resolution to the router it wraps. A non-resolver responder simply
//  does not conform.
//

import HTTPCore
import Testing
import WebSocket

@testable import HTTPServer

@Suite("RouteResolver — head-time route metadata")
struct RouteResolverTests {
    private func handler() -> Route.Handler { { _, _, _ in .text("ok") } }

    @Test("Router resolves a matched route's metadata from method + path")
    func resolvesMetadata() throws {
        let router = Router {
            Route(
                .post,
                Route.parse("/upload"),
                handler: handler(),
                middleware: [],
                bodyLimit: 1_024,
                streamsBody: true
            )
        }
        let matched = try #require(router.match(method: .post, path: "/upload"))
        #expect(matched.route.bodyLimit == 1_024)
        #expect(matched.route.streamsBody)
        #expect(matched.route.webSocketHandler == nil)
    }

    @Test("Router.match returns nil for an unmatched path or method")
    func resolveMiss() {
        let router = Router { Route.get("/a") { _, _, _ in .text("a") } }
        #expect(router.match(method: .get, path: "/b") == nil)
        #expect(router.match(method: .post, path: "/a") == nil)
    }

    @Test("Router.match folds HEAD onto the GET route (RFC 9110 §9.3.2)")
    func resolveHeadFold() throws {
        let router = Router {
            Route(.get, Route.parse("/a"), handler: handler(), middleware: [], bodyLimit: 7)
        }
        let matched = try #require(router.match(method: .head, path: "/a"))
        #expect(matched.route.bodyLimit == 7)
    }

    @Test("an upgrade match finds a WS route by path, ignoring method, and sets hasWebSocketRoutes")
    func resolvesWebSocket() throws {
        let socket = ClosureWebSocketHandler { _ in [] }
        let router = Router {
            Route(
                .get,
                Route.parse("/chat"),
                handler: handler(),
                middleware: [],
                webSocketHandler: socket
            )
        }
        // An Extended CONNECT arrives as CONNECT against a route declared GET (RFC 8441 §4).
        let upgrade = try #require(
            router.match(method: .connect, path: "/chat", isUpgrade: true)
        )
        #expect(upgrade.route.webSocketHandler != nil)
        #expect(router.match(method: .connect, path: "/nope", isUpgrade: true) == nil)
        // Without the flag, CONNECT matches nothing: the route is declared GET.
        #expect(router.match(method: .connect, path: "/chat") == nil)
        #expect(router.hasWebSocketRoutes)
    }

    @Test("hasWebSocketRoutes is false when no route declares a handler")
    func noWebSocketRoutes() {
        let router = Router { Route.get("/a") { _, _, _ in .text("a") } }
        #expect(router.hasWebSocketRoutes == false)
    }

    @Test("a MiddlewareChain forwards resolution to the wrapped router")
    func chainForwards() {
        let router = Router {
            Route(.get, Route.parse("/a"), handler: handler(), middleware: [], bodyLimit: 42)
        }
        // `MiddlewareChain` conforms to `RouteResolver` concretely; bind it as the existential to call
        // through the forwarding seam.
        let resolver: any RouteResolver = MiddlewareChain(
            [ServerHeaderMiddleware("x")], terminatingAt: router
        )
        #expect(resolver.match(method: .get, path: "/a", isUpgrade: false)?.route.bodyLimit == 42)
        #expect(resolver.hasWebSocketRoutes == false)
    }

    @Test("a multi-link wrapped(by:) chain forwards resolution to the terminal router")
    func wrappedChainForwards() throws {
        let socket = ClosureWebSocketHandler { _ in [] }
        let router = Router {
            Route(
                .get,
                Route.parse("/chat"),
                handler: handler(),
                middleware: [],
                webSocketHandler: socket
            )
        }
        let wrapped = router.wrapped(by: [ServerHeaderMiddleware("a"), ServerHeaderMiddleware("b")])
        let resolver = try #require(wrapped as? (any RouteResolver))
        #expect(
            resolver.match(method: .get, path: "/chat", isUpgrade: true)?
                .route.webSocketHandler != nil
        )
        #expect(resolver.hasWebSocketRoutes)
    }

    @Test("a non-resolver responder does not conform to RouteResolver")
    func nonResolver() {
        let responder = ClosureResponder { _, _, _ in .text("x") }
        #expect((responder as? (any RouteResolver)) == nil)
    }
}
