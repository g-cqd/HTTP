//
//  SanitizedRequest.swift
//  HTTPCore
//
//  A request that has been through the server-asserted strip — proved by the fact that it exists.
//
//  RFC 9110 §17.1 puts the burden of a field's meaning on the recipient, so a server must never accept
//  an assertion it did not itself make: a handler reading `X-Auth-Subject` is reading an authorization
//  decision, and a peer that can set it from the wire has made that decision for the server (CWE-290,
//  authentication bypass by spoofing; CWE-807, reliance on an untrusted input in a security decision).
//  Audit CR-F13 answered that with one ingress choke point, and audit R5-SEC1 found the answer was not
//  enough: the HTTP/2 and HTTP/3 Extended CONNECT paths (RFC 8441 / RFC 9220) take a request straight
//  off the engine event and hand it to the WebSocket upgrade seam, bypassing the choke point entirely.
//
//  A second choke point would have had the same defect — it can be forgotten again by the next path
//  added. So the strip is a *type* instead. `SanitizedRequest` has exactly one initializer and that
//  initializer strips, so possessing a value of this type is proof the strip ran; a seam that takes one
//  cannot be handed an unsanitized request, and forgetting is a compile error rather than a review
//  note. That is the difference between an invariant and a convention.
//
//  It stays a thin wrapper rather than re-exposing `HTTPRequest`'s surface: the point is that the
//  wrapper is unforgeable, and every use site reads `.request` explicitly, which is exactly the moment
//  a reader should be reminded which request this is.
//

/// A request with every ``HTTPFieldName/serverAsserted`` field removed (RFC 9110 §17.1).
///
/// The only way to obtain one is to construct one, and construction performs the strip — so a value of
/// this type *is* the guarantee. Seams that make security decisions from request fields (the WebSocket
/// upgrade authorization, RFC 6455 §4) take this rather than an `HTTPRequest`.
public struct SanitizedRequest: Sendable {
    /// The request, with every server-asserted field already removed.
    public let request: HTTPRequest

    /// Strips every server-asserted field from `request`.
    ///
    /// The mutation is guarded per field, so a request carrying none of them — every ordinary request —
    /// triggers no copy-on-write of the field storage and the strip costs one lookup per name.
    public init(_ request: HTTPRequest) {
        var request = request
        for name in HTTPFieldName.serverAsserted where request.headerFields[name] != nil {
            request.headerFields.removeAll(named: name)
        }
        self.request = request
    }
}
