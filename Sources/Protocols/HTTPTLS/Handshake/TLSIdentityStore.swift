//
//  TLSIdentityStore.swift
//  HTTPTLS
//
//  Hot identity reload (Phase 3c) — the engine-side twin of the portable backbone's
//  `reload(tls:)` (a `Mutex`-guarded `SSL_CTX` swap): one long-lived store per listener,
//  handed to EVERY connection; ``replace(with:)`` swaps the selector atomically. A
//  connection resolves its identity at ClientHello time (see ``TLSIdentitySelector``), so
//  handshakes that begin after the swap serve the new identity while established
//  connections keep serving — the identity is never consulted again after the server's
//  Certificate flight. The contract for the transport (Phase 3d): construct each
//  `TLSServerConnection` with the listener's store (`init(configuration:identitySelector:)`);
//  reload = one `replace(with:)` on the store, no listener restart, no port rebind.
//

internal import Synchronization

/// A reloadable identity selector: swap identities for new handshakes atomically.
public final class TLSIdentityStore: TLSIdentitySelector, Sendable {
    /// The current selector (a whole catalog swaps at once — never a torn default/SNI mix).
    private let current: Mutex<any TLSIdentitySelector>

    /// Creates the store with its initial selector.
    public init(_ initial: any TLSIdentitySelector) {
        current = Mutex(initial)
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Convenience: a single-identity store (an empty ``TLSIdentityCatalog``).
    public convenience init(identity: any TLSIdentityProvider) {
        self.init(TLSIdentityCatalog(defaultIdentity: identity))
    }

    /// Atomically replaces the selector — handshakes that resolve after this call serve
    /// the new identities; established connections are unaffected.
    public func replace(with selector: any TLSIdentitySelector) {
        current.withLock { $0 = selector }
    }

    /// Resolves against the CURRENT selector (one lock hop per handshake, at ClientHello).
    public func identity(forServerName name: String?) -> any TLSIdentityProvider {
        current.withLock { $0.identity(forServerName: name) }
    }
}
