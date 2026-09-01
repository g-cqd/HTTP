//
//  SessionStore.swift
//  HTTPServer
//
//  The server-side half of session management (RFC 6265bis): a store of live session ids that
//  ``SessionMiddleware`` can consult so a session can be *revoked* (logout) or timed out while idle.
//  Optional — without a store the middleware stays stateless (the signed cookie is the whole session).
//  Conformers may be remote (Redis, a database), so the methods are `async`; an in-memory
//  ``InMemorySessionStore`` ships.
//
//  A store is **not** what bounds a session's absolute lifetime (audit R5-SEC2). That is the expiry
//  ``SessionMiddleware`` signs into the token, checked before a store is ever consulted, so every
//  configuration has the bound whether or not one is installed. A store adds the two guarantees a
//  self-contained token cannot make: revocation before the expiry, and an idle timeout.
//

/// A store of live server-side sessions consulted by ``SessionMiddleware`` for revocation and expiry.
public protocol SessionStore: Sendable {
    /// Whether `id` is a live session — refreshing its sliding TTL — and `false` once it has expired,
    /// been revoked, or was never registered.
    func validate(_ id: String) async -> Bool

    /// Records a freshly minted session `id` as live (called when the middleware issues a new session).
    func register(_ id: String) async

    /// Revokes `id` (e.g. on logout) so a later ``validate(_:)`` returns `false`.
    func revoke(_ id: String) async
}
