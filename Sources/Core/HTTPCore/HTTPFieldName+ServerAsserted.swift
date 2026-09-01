//
//  HTTPFieldName+ServerAsserted.swift
//  HTTPCore
//
//  RFC 9110 §17.1 — the fields the *server* asserts, and a client therefore may not. A field's meaning
//  is whatever the recipient's own processing makes of it, so a recipient must never accept an
//  assertion it did not itself make: a handler reading `X-Auth-Subject` is reading an authorization
//  decision, and a peer that can set it from the wire has made that decision for it (CWE-290 —
//  authentication bypass by spoofing; CWE-807 — reliance on an untrusted input in a security decision).
//
//  Declared once, here, so the set cannot drift away from the per-field doc comments that promise the
//  strip. The server strips exactly this list at ingress; a field added to it is stripped with no
//  further change, and the ingress regression suite is parameterized over it so an addition that the
//  strip somehow misses fails a test rather than shipping.
//

extension HTTPFieldName {
    /// The request fields the server asserts for handlers, stripped from every inbound request.
    ///
    /// A client-supplied value on any of these is a spoof attempt, never a hop-by-hop convention: each
    /// is set — if at all — by the server or by a middleware running above the handler, after the fact
    /// it asserts has actually been verified. The server removes all of them the moment a request head
    /// is turned into a ``RequestContext``, so an asserting middleware that decides *not* to assert
    /// (an authorizer that returns no subject, a verified token with no `sub`) leaves the handler with
    /// no value rather than with the client's.
    ///
    /// Deliberately **not** here: `X-Forwarded-For` and the RFC 7239 `Forwarded` field, which are
    /// genuine hop-by-hop proxy conventions whose whole purpose is to arrive from the wire. Those are
    /// gated by a trusted-proxy policy (``ForwardedAddress``) rather than stripped.
    public static let serverAsserted: [HTTPFieldName] = [
        .xRequestID, .xSessionID, .xAuthSubject, .xClientCertSubject
    ]
}
