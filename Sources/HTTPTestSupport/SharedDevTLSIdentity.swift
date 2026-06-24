//
//  SharedDevTLSIdentity.swift
//  HTTPTestSupport
//
//  A dev TLS identity minted once per test process and reused. `DevTLSIdentity.selfSigned` shells out
//  to `openssl`, so minting it per test would be slow and spawn many processes (a source of
//  environmental flakiness on a busy parallel runner); caching the bytes behind a `Mutex` mints them
//  exactly once. (The PKCS#12 *import* is separately serialized inside the Network backbone, since
//  `SecPKCS12Import` is not thread-safe.)
//

public import HTTPTransport
internal import Synchronization

/// A process-wide, lazily-minted self-signed dev TLS identity for tests.
public enum SharedDevTLSIdentity {
    private static let cache = Mutex<TransportTLS?>(nil)

    /// The shared dev identity, minting it on first use and returning the cached value thereafter.
    public static func value() throws -> TransportTLS {
        try cache.withLock { cached in
            if let cached {
                return cached
            }
            let identity = try DevTLSIdentity.selfSigned()
            cached = identity
            return identity
        }
    }
}
