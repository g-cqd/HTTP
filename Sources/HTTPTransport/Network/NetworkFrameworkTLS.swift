//
//  NetworkFrameworkTLS.swift
//  HTTPTransport
//
//  The single place the Network backbone touches the C `sec_protocol_*` / `SecPKCS12Import` surface.
//  Each entry point validates its `OSStatus` / optional return and fails closed with a typed
//  `TransportError`, so the rest of the backbone never handles a raw pointer, a CF cast, or an
//  `OSStatus` — the unsafe interop is bounded here. Everything below runs once per connection
//  (handshake setup, or once at `.ready`), never on the byte path, so the wrapping costs nothing
//  measurable against the 200k-rps budget.
//
//  Standards: PKCS#12 (RFC 7292) identities; ALPN (RFC 7301) selects "h2" for HTTP/2 over TLS
//  (RFC 9113 §3.3); the negotiated TLS floor is 1.3 (RFC 8446).
//

internal import Foundation
internal import Network
internal import Security
internal import Synchronization

/// Safe Swift wrappers over the Security/Network C TLS APIs used by the Network backbone.
enum NetworkFrameworkTLS {

    /// Serializes `SecPKCS12Import`, which is not thread-safe: concurrent calls intermittently fail
    /// with an internal/MAC error (`errSecPkcs12VerifyFailure`).
    ///
    /// A server imports its identity once at listener start, so the lock is uncontended in production
    /// — it costs nothing and removes a race that only surfaces when many TLS handshakes are set up at
    /// once (e.g. a parallel test suite).
    private static let importLock = Mutex<Void>(())

    /// Imports a PKCS#12 (RFC 7292) blob into a `sec_identity_t`, failing closed on any error.
    ///
    /// Wraps `SecPKCS12Import` + `sec_identity_create`: a non-success `OSStatus`, a blob with no
    /// identity, a value that is not a `SecIdentity`, or a `nil` `sec_identity_t` each surface as a
    /// `TransportError.tlsConfigurationFailed` rather than a force-cast or a silent `nil`. The import
    /// step is serialized (see ``importLock``).
    static func identity(pkcs12: [UInt8], passphrase: String) throws -> sec_identity_t {
        let options = [kSecImportExportPassphrase as String: passphrase] as CFDictionary
        // `SecPKCS12Import` is serialized (see `importLock`). `rawItems` is local to this call and
        // only written inside the lock, so reading it afterwards is sound — hence `nonisolated(unsafe)`.
        nonisolated(unsafe) var rawItems: CFArray?
        let status = importLock.withLock { _ in
            SecPKCS12Import(Data(pkcs12) as CFData, options, &rawItems)
        }
        guard status == errSecSuccess else {
            throw TransportError.tlsConfigurationFailed(
                "SecPKCS12Import failed (OSStatus \(status))")
        }
        guard let items = rawItems as? [[String: AnyObject]],
            let identityValue = items.first?[kSecImportItemIdentity as String]
        else {
            throw TransportError.tlsConfigurationFailed("PKCS#12 contained no identity")
        }
        // Verify the CoreFoundation type id, then bind it. `as?` is rejected as "always succeeds" for
        // CF types and `as!` is banned, so — having proven the type — `unsafeDowncast` is the sound,
        // allocation-free primitive (it is safe precisely because the guard established the type).
        guard CFGetTypeID(identityValue) == SecIdentityGetTypeID() else {
            throw TransportError.tlsConfigurationFailed("PKCS#12 identity was not a SecIdentity")
        }
        let secIdentity = unsafeDowncast(identityValue, to: SecIdentity.self)
        guard let identity = sec_identity_create(secIdentity) else {
            throw TransportError.tlsConfigurationFailed("sec_identity_create returned nil")
        }
        return identity
    }

    /// Builds `NWProtocolTLS.Options` advertising `applicationProtocols` (ALPN, RFC 7301) and the
    /// server `identity`, with a TLS 1.3 floor (RFC 8446; required for the h2/h3 secure path).
    static func options(
        identity: sec_identity_t,
        applicationProtocols: [String]
    ) -> NWProtocolTLS.Options {
        let options = NWProtocolTLS.Options()
        let security = options.securityProtocolOptions
        sec_protocol_options_set_local_identity(security, identity)
        sec_protocol_options_set_min_tls_protocol_version(security, .TLSv13)
        // ALPN strings are short ASCII tokens; `withCString` hands the C API a valid pointer for the
        // call's duration only — no retained pointer, no allocation beyond the transient buffer.
        for proto in applicationProtocols {
            proto.withCString { sec_protocol_options_add_tls_application_protocol(security, $0) }
        }
        return options
    }

    /// The ALPN-negotiated application protocol of a ready `connection` (RFC 7301), or `nil` when the
    /// connection is cleartext, the handshake has not completed, or no protocol was selected.
    static func negotiatedApplicationProtocol(of connection: NWConnection) -> String? {
        guard
            let metadata = connection.metadata(definition: NWProtocolTLS.definition)
                as? NWProtocolTLS.Metadata,
            let raw = sec_protocol_metadata_get_negotiated_protocol(
                metadata.securityProtocolMetadata)
        else {
            return nil
        }
        return String(cString: raw)
    }
}
