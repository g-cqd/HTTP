//
//  TLSIdentitySelector.swift
//  HTTPTLS
//
//  The SNI multi-cert seam (RFC 6066 §3, Phase 3c): the connection resolves its identity
//  from the ClientHello's `server_name` BEFORE any ServerHello output — the same point the
//  portable backbone's libssl `servername` callback fires. Selection must be total (a
//  server always has SOME identity to serve): fallbacks are the selector's policy, which is
//  why this returns a provider rather than an optional — the portable semantics (exact
//  match, else the default identity; RFC 6066's `unrecognized_name` alert is deliberately
//  not sent, matching both backbones and common practice).
//

/// Picks the certificate identity for one handshake from the client's SNI (RFC 6066 §3).
public protocol TLSIdentitySelector: Sendable {
    /// The identity to serve for `name` (the ClientHello's `server_name` host, or nil when
    /// the client sent none). Called once per handshake, before the ServerHello.
    func identity(forServerName name: String?) -> any TLSIdentityProvider
}
