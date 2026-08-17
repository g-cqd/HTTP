//
//  TLSIdentityCatalog.swift
//  HTTPTLS
//
//  The standard ``TLSIdentitySelector``: a default identity plus a per-server-name map —
//  the `TransportTLS.sniIdentities` shape, with the portable backbone's exact selection
//  semantics (its SNI callback is a byte-exact `strcmp`): exact host match wins; an
//  unmatched name, or a client that sends no SNI, gets the default. No case folding —
//  RFC 6066 §3 sends host names as lowercase A-labels already, and folding here would
//  diverge from what the portable backbone serves for the same ClientHello.
//

/// A default identity plus SNI-selected per-name identities (RFC 6066 §3).
public struct TLSIdentityCatalog: TLSIdentitySelector {
    /// The identity served when no SNI name matches (or none was sent).
    public var defaultIdentity: any TLSIdentityProvider
    /// Per-server-name identities, keyed by the exact `server_name` host.
    public var sniIdentities: [String: any TLSIdentityProvider]

    /// Creates a catalog (single-identity when `sniIdentities` stays empty).
    public init(
        defaultIdentity: any TLSIdentityProvider,
        sniIdentities: [String: any TLSIdentityProvider] = [:]
    ) {
        self.defaultIdentity = defaultIdentity
        self.sniIdentities = sniIdentities
    }

    /// Exact match on the offered host, else the default (the portable-TLS semantics).
    public func identity(forServerName name: String?) -> any TLSIdentityProvider {
        guard let name, let matched = sniIdentities[name] else {
            return defaultIdentity
        }
        return matched
    }
}
