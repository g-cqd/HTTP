//
//  RequestStorageKey.swift
//  HTTPServer
//
//  A type-safe key into ``RequestContext``'s per-request storage bag (an `EnvironmentValues`-style
//  pattern): the conforming type is a phantom key whose ``Value`` fixes what the bag stores and returns
//  under it, so a read needs no cast and a middleware and the handler below it agree on the type by
//  construction.
//

/// A type-safe key into the ``RequestContext`` storage bag.
///
/// ```swift
/// enum AuthenticatedUser: RequestStorageKey { typealias Value = User }
/// // middleware: context[AuthenticatedUser.self] = user
/// // handler:    let user = context[AuthenticatedUser.self]
/// ```
public protocol RequestStorageKey {
    /// The type of value stored under this key.
    associatedtype Value: Sendable
}
