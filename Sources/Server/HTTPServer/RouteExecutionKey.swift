//
//  RouteExecutionKey.swift
//  HTTPServer
//
//  The identity ``HandlerExecutionGate`` keys its service-time measurements on (audit CR-F7).
//
//  "How long does this route take?" is only a meaningful question per route, so the adaptive policy
//  needs a hashable name for the table entry a request matched. ``RouteMatch/Handle`` already carries
//  exactly that — the identity of the router that minted the match and the index of the entry within
//  its table — because the dispatch-plan work (CR-F12 / CR-F19) needed to prove a match belonged to
//  the table about to run it. This reuses that pair rather than inventing a second naming scheme, and
//  in particular does NOT key on the request path: a parameterized route would then mint one bucket
//  per distinct URL, which is unbounded and attacker-chosen (CWE-770).
//
//  A match minted by a ``RouteResolver`` other than a ``Router`` carries no handle, and a request
//  that matched nothing has no route at all. Both are unnameable, so both fall into one shared
//  ``unrouted`` bucket. The consequence is documented rather than hidden: under a custom resolver the
//  adaptive policy measures the responder as a whole rather than route by route, which degrades to a
//  coarser but still correct decision.
//

/// A hashable name for the route whose handler service time is being measured.
struct RouteExecutionKey: Hashable, Sendable {
    /// The identity of the router that minted the match — `0` for ``unrouted``.
    private let router: UInt64

    /// The index of the entry within that router's table — negative for ``unrouted``.
    private let index: Int

    /// The shared bucket for requests with no nameable route.
    ///
    /// `RouterIdentity.mint()` is a pre-increment counter, so it never issues `0` and this can never
    /// collide with a real table entry.
    static let unrouted = Self(router: 0, index: -1)

    private init(router: UInt64, index: Int) {
        self.router = router
        self.index = index
    }

    /// Names the table entry `match` came from, or `nil` when it has no nameable route.
    ///
    /// `nil` means the caller should use ``unrouted``; it is spelled as a failable initializer so the
    /// two cases stay distinguishable at the call site and in tests.
    init?(_ match: RouteMatch?) {
        guard let handle = match?.handle else {
            return nil
        }
        self.init(router: handle.origin.value, index: handle.index)
    }
}
