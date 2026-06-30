//
//  RouteResolverTests.swift
//  HTTPServerTests
//
//  The head-time route-metadata seam (Phase 1 foundation): ``Router`` resolves a route's body limit,
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
        let resolved = try #require(router.resolve(method: .post, path: "/upload"))
        #expect(resolved.bodyLimit == 1_024)
        #expect(resolved.streamsBody)
        #expect(resolved.webSocketHandler == nil)
    }

    @Test("Router.resolve returns nil for an unmatched path or method")
    func resolveMiss() {
        let router = Router { Route.get("/a") { _, _, _ in .text("a") } }
        #expect(router.resolve(method: .get, path: "/b") == nil)
        #expect(router.resolve(method: .post, path: "/a") == nil)
    }

    @Test("Router.resolve folds HEAD onto the GET route (RFC 9110 §9.3.2)")
    func resolveHeadFold() throws {
        let router = Router {
            Route(.get, Route.parse("/a"), handler: handler(), middleware: [], bodyLimit: 7)
        }
        let resolved = try #require(router.resolve(method: .head, path: "/a"))
        #expect(resolved.bodyLimit == 7)
    }

    @Test("resolveWebSocket finds a WS route by path, ignoring method, and sets hasWebSocketRoutes")
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
        #expect(try #require(router.resolveWebSocket(path: "/chat")).webSocketHandler != nil)
        #expect(router.resolveWebSocket(path: "/nope") == nil)
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
        #expect(resolver.resolve(method: .get, path: "/a")?.bodyLimit == 42)
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
        #expect(resolver.resolveWebSocket(path: "/chat")?.webSocketHandler != nil)
        #expect(resolver.hasWebSocketRoutes)
    }

    @Test("a non-resolver responder does not conform to RouteResolver")
    func nonResolver() {
        let responder = ClosureResponder { _, _, _ in .text("x") }
        #expect((responder as? (any RouteResolver)) == nil)
    }
}
