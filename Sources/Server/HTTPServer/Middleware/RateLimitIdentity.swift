//
//  RateLimitIdentity.swift
//  HTTPServer
//
//  What "a client" means to ``RateLimitMiddleware``. This used to be a closure defaulting to the
//  request authority — the `Host` / `:authority` value — which is the one thing on a request that is
//  both fully attacker-controlled and shared by every legitimate caller. That default failed in both
//  directions at once: every honest client of `api.example.com` drew on one budget, so a single busy
//  caller starved the rest, while an attacker simply varied the header to obtain an unlimited number
//  of fresh budgets — and, incidentally, an unlimited number of tracking-map entries (CWE-770,
//  CWE-807: reliance on an untrusted input in a security decision).
//
//  The default is now the verified transport peer, which the server observes rather than accepts. A
//  proxy chain can be honored instead, but only through an explicit trust boundary (RFC 7239 §8.1).
//  IPv6 is aggregated to a prefix because a single subscriber is routinely allocated a whole /64
//  (RFC 6177 §2), so a per-address budget is walked around by cycling through the subnet.
//

public import HTTPCore
public import HTTPTransport

/// How ``RateLimitMiddleware`` decides which budget a request draws on.
public enum RateLimitIdentity: Sendable {
    /// The verified transport peer address, aggregated to `ipv6Prefix` bits for IPv6 — the default.
    ///
    /// Server-observed: it comes from the socket, so no header can move a request onto somebody
    /// else's budget or mint a fresh one.
    case peerAddress(ipv6Prefix: UInt8 = 64)

    /// The client address a proxy chain reports, believed only when the peer is inside `trusting`.
    ///
    /// For a server behind a load balancer or CDN, where the transport peer is always the proxy.
    /// `trusting` must list exactly the hops the operator runs (``IPPrefixSet/loopback``,
    /// ``IPPrefixSet/privateUse``, or the CDN's published ranges); with ``IPPrefixSet/none`` the
    /// header is ignored and this degrades to ``peerAddress(ipv6Prefix:)``. Trusting too much is a
    /// full bypass — every client could then name its own budget (RFC 7239 §8.1).
    case forwardedFor(trusting: IPPrefixSet, ipv6Prefix: UInt8 = 64)

    /// An application-supplied identity — an API key, an authenticated subject, a tenant id.
    ///
    /// Whatever it returns becomes the budget key, so it must be something the server verified. Two
    /// requests that return the same string share one budget.
    case custom(@Sendable (HTTPRequest, RequestContext) -> String)

    /// The key for a request whose provenance is unknown — one shared budget for all of them.
    ///
    /// Fail-closed by design: a synthetic context (a test, a direct responder call) has no peer, and
    /// pooling those into a single budget is strictly safer than falling back to a client-supplied
    /// header, which is exactly the bug this type replaced.
    public static let unattributed = "-"

    /// The budget key for `request` arriving on `context`.
    func key(for request: HTTPRequest, context: RequestContext) -> String {
        switch self {
            case .peerAddress(let ipv6Prefix):
                return Self.aggregated(context.connection.peer?.ipAddress, ipv6Prefix: ipv6Prefix)
            case .forwardedFor(let trusting, let ipv6Prefix):
                guard let peer = context.connection.peer?.ipAddress else {
                    return Self.unattributed
                }
                let reported = ForwardedAddress.client(
                    request.headerFields,
                    peer: peer,
                    trusting: trusting
                )
                return Self.aggregated(reported ?? peer, ipv6Prefix: ipv6Prefix)
            case .custom(let resolve):
                return resolve(request, context)
        }
    }

    /// `address` as a budget key, with IPv6 folded to its `ipv6Prefix` network (RFC 6177 §2).
    private static func aggregated(_ address: IPAddress?, ipv6Prefix: UInt8) -> String {
        guard let address else {
            return unattributed
        }
        guard case .v6 = address else {
            return address.canonicalText
        }
        return address.masked(to: ipv6Prefix).canonicalText
    }
}
