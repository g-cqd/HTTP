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

    /// The queue Network.framework invokes the mutual-TLS verify block on (once per handshake, never
    /// on the byte path).
    ///
    /// Concurrent so parallel handshakes verify independently.
    private static let verifyQueue = DispatchQueue(
        label: "http.transport.network-framework.tls-verify",
        attributes: .concurrent
    )

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
                "SecPKCS12Import failed (OSStatus \(status))"
            )
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
    /// server `identity`, pinning the TLS version range (RFC 8446 / RFC 9325; default TLS 1.3-only),
    /// and — when `clientAuth` is `.required` — requesting and verifying a client certificate (mTLS).
    // swiftlint:disable discouraged_default_parameter - secure TLS 1.3 default
    static func options(
        identity: sec_identity_t,
        applicationProtocols: [String],
        minVersion: TLSVersion = .tlsV13,
        maxVersion: TLSVersion = .tlsV13,
        clientAuth: TransportTLS.ClientAuth = .none,
        verifyPeer: (@Sendable ([[UInt8]]) -> Bool)? = nil
    ) -> NWProtocolTLS.Options {
        // swiftlint:enable discouraged_default_parameter
        let options = NWProtocolTLS.Options()
        let security = options.securityProtocolOptions
        sec_protocol_options_set_local_identity(security, identity)
        sec_protocol_options_set_min_tls_protocol_version(security, protocolVersion(minVersion))
        // Pin the ceiling too (audit T-F5): without a max, a future OS draft/experimental version
        // could be negotiated unintentionally (RFC 9325 / BCP 195 defense-in-depth).
        sec_protocol_options_set_max_tls_protocol_version(security, protocolVersion(maxVersion))
        // ALPN strings are short ASCII tokens; `withCString` hands the C API a valid pointer for the
        // call's duration only — no retained pointer, no allocation beyond the transient buffer.
        for proto in applicationProtocols {
            proto.withCString { sec_protocol_options_add_tls_application_protocol(security, $0) }
        }
        if clientAuth == .required {
            configureMutualTLS(security, verifyPeer: verifyPeer)
        }
        return options
    }

    /// Configures mutual TLS (RFC 8446 §4.4.2) on `security`: request + require a client certificate,
    /// and install a verify block handing the DER chain (leaf-first) to the caller's trust hook.
    ///
    /// The verify block is what lets a self-signed or privately-issued client cert be accepted at all —
    /// the platform's default trust evaluation would reject it — so a `nil` `verifyPeer` accepts any
    /// *presented* chain (presence is still enforced by the required flag) and a hook returning `false`
    /// fails the handshake. Both the flag and the block are needed: the flag makes the server send the
    /// CertificateRequest, the block decides acceptance.
    private static func configureMutualTLS(
        _ security: sec_protocol_options_t,
        verifyPeer: (@Sendable ([[UInt8]]) -> Bool)?
    ) {
        sec_protocol_options_set_peer_authentication_required(security, true)
        let verify: sec_protocol_verify_t = { metadata, _, complete in
            let chain = peerCertificates(in: metadata)
                .map {
                    [UInt8](SecCertificateCopyData($0) as Data)
                }
            complete(verifyPeer?(chain) ?? !chain.isEmpty)
        }
        sec_protocol_options_set_verify_block(security, verify, verifyQueue)
    }

    /// Maps a backbone-agnostic ``TLSVersion`` to the Security framework's `tls_protocol_version_t`.
    private static func protocolVersion(_ version: TLSVersion) -> tls_protocol_version_t {
        switch version {
            case .tlsV12:
                .TLSv12
            case .tlsV13:
                .TLSv13
        }
    }

    /// The ALPN-negotiated application protocol of a ready `connection` (RFC 7301), or `nil` when the
    /// connection is cleartext, the handshake has not completed, or no protocol was selected.
    static func negotiatedApplicationProtocol(of connection: NWConnection) -> String? {
        guard
            let metadata = connection.metadata(definition: NWProtocolTLS.definition)
                as? NWProtocolTLS.Metadata,
            let raw = sec_protocol_metadata_get_negotiated_protocol(
                metadata.securityProtocolMetadata
            )
        else {
            return nil
        }
        return String(cString: raw)
    }

    /// The subject summary of the peer's leaf client certificate (mutual TLS) on a ready `connection`,
    /// or `nil` when no client certificate was presented (cleartext / one-way TLS / no peer cert).
    ///
    /// The chain is leaf-first, so `.first` is the end-entity certificate whose
    /// `SecCertificateCopySubjectSummary` (e.g. the CN) identifies the client.
    static func peerSubject(of connection: NWConnection) -> String? {
        guard
            let metadata = connection.metadata(definition: NWProtocolTLS.definition)
                as? NWProtocolTLS.Metadata,
            let leaf = peerCertificates(in: metadata.securityProtocolMetadata).first,
            let summary = SecCertificateCopySubjectSummary(leaf)
        else {
            return nil
        }
        return summary as String
    }

    /// The peer's certificate chain (leaf-first) as `SecCertificate`s, from TLS handshake `metadata`.
    ///
    /// `sec_certificate_copy_ref` returns a +1 reference that `takeRetainedValue` adopts (no leak); the
    /// access closure runs synchronously for each chain element before the call returns.
    private static func peerCertificates(
        in metadata: sec_protocol_metadata_t
    ) -> [SecCertificate] {
        var chain: [SecCertificate] = []
        _ = sec_protocol_metadata_access_peer_certificate_chain(metadata) { secCertificate in
            chain.append(sec_certificate_copy_ref(secCertificate).takeRetainedValue())
        }
        return chain
    }
}
