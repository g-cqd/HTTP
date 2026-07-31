//
//  RouterIdentity.swift
//  HTTPServer
//
//  A value identity for a ``Router``, minted once per table.
//
//  A `Router` is a `struct`, so it has no object identity to compare — but a ``RouteMatch`` resolved
//  from a request head and carried forward to dispatch has to be *provably* a match against the table
//  that is about to run it. A hot reload can replace the table between those two moments, and a nested
//  or wrapped router can hand a match to a responder that is not the one that produced it; in both
//  cases indexing blindly into "the" table would dispatch the wrong handler. Tagging the match with the
//  identity of the router that minted it turns that into a cache miss (fall back to a normal scan)
//  rather than a mis-dispatch.
//
//  Copies of a `Router` value share an identity, which is correct: the route table is immutable, so two
//  copies are the same table and an index means the same thing in both.
//

internal import Synchronization

/// A route table's identity.
///
/// Minted per ``Router``; copies of a router value share it, because they are the same table.
struct RouterIdentity: Sendable, Hashable {
    let value: UInt64

    /// The source of identities — process-wide and monotonic, so no two tables collide.
    ///
    /// A wrapping add is sound at any conceivable rate of router construction: 2^64 tables would have
    /// to be built for a value to repeat, and a repeat is only a mis-dispatch if the *earlier* router's
    /// match is still in flight 2^64 constructions later.
    private static let counter = Atomic<UInt64>(0)

    /// A fresh identity, distinct from every other minted in this process.
    static func mint() -> Self {
        Self(value: counter.wrappingAdd(1, ordering: .relaxed).newValue)
    }
}
