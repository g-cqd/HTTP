//
//  CountingRouter.swift
//  HTTPServerTests
//
//  A ``Router`` that counts how many times the server walked its table for one request, and reports
//  each head-time resolution on a probe so a test can order a `reloadResponder` against it without
//  sleeping.
//
//  Two audit findings need exactly this instrument. CR-F12 (a reload between head parse and dispatch
//  can pair one generation's body limit with another's handler) needs to *observe the moment the head
//  resolved* to stage the reload deterministically. CR-F19 (the table is walked 2–4 times per request)
//  needs the walk count itself to be an assertion rather than a reading of the source.
//

import HTTPCore
import HTTPTestSupport
import Synchronization

@testable import HTTPServer

/// A router that tallies its own table walks and announces each head-time resolution.
final class CountingRouter: HTTPRouter {
    /// The wrapped table — the real ``Router``, so the counts measure the production path.
    private let router: Router

    /// Table walks so far: every head-time resolution plus every dispatch-time match.
    private let walks = Mutex(0)

    /// Announces each head-time resolution, so a test can act between the head and the dispatch.
    private let resolved: AsyncEventProbe<String>?

    /// Builds a counting router over `routes`, reporting head-time resolutions on `resolved`.
    init(resolved: AsyncEventProbe<String>? = nil, @RouteBuilder _ routes: () -> [Route]) {
        self.router = Router(routes)
        self.resolved = resolved
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// How many times the table has been walked since this router was built.
    var walkCount: Int { walks.withLock(\.self) }

    /// Resets the tally — call it between the requests of a multi-request test.
    func resetWalkCount() { walks.withLock { $0 = 0 } }

    // MARK: HTTPResponder

    func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext
    ) async -> ServerResponse {
        walks.withLock { $0 += 1 }
        return await router.respond(to: request, body: body, context: context)
    }

    // MARK: RouteResolver

    func match(method: HTTPMethod, path: String, isUpgrade: Bool) -> RouteMatch? {
        walks.withLock { $0 += 1 }
        resolved?.record(path)
        return router.match(method: method, path: path, isUpgrade: isUpgrade)
    }

    var hasWebSocketRoutes: Bool { router.hasWebSocketRoutes }
}
