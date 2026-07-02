//
//  OpenSSLTLS.swift
//  HTTPTransport
//
//  The single place the portable TLS backbone touches the libssl `SSL_CTX` surface — the mirror of
//  `NetworkFrameworkTLS` for the Network backbone (ADR 0004). Builds a server `SSL_CTX` from the
//  backbone-agnostic `TransportTLS` (the same PKCS#12 identity + ALPN + version policy the Network
//  path uses), and reads handshake metadata. All libssl calls go through the `CHTTPBoringSSLShims` shim,
//  so the unsafe interop stays bounded here; every entry point fails closed to a typed
//  `TransportError`.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — present only in the opt-in portable build (`HTTP_PORTABLE_TLS`).
//
//  Standards: TLS 1.3 (RFC 8446 / RFC 9325 floor); ALPN (RFC 7301) selects "h2"/"http/1.1"; PKCS#12
//  identities (RFC 7292).
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims

    /// Safe Swift wrappers over the libssl `SSL_CTX` configuration used by the portable backbone.
    enum OpenSSLTLS {
        /// Builds the server `SSL_CTX` from `tls` — the default identity plus, when ``sniIdentities``
        /// is non-empty, a per-server-name context and an SNI selection callback (RFC 6066 §3).
        ///
        /// The caller owns the returned (default) context and must `CHTTPBoringSSL_SSL_CTX_free` it once no live `SSL`
        /// references it; freeing it also releases the SNI registry and its per-name contexts.
        static func serverContext(_ tls: TransportTLS) throws -> OpaquePointer {
            let context = try makeContext(identity: .from(tls), tls: tls)
            guard !tls.sniIdentities.isEmpty else {
                return context
            }
            do {
                CHTTPBoringSSLShims_enable_sni(context)
                for (name, identity) in tls.sniIdentities {
                    let perName = try makeContext(
                        identity: .pkcs12(identity.pkcs12, passphrase: identity.passphrase),
                        tls: tls
                    )
                    name.withCString { CHTTPBoringSSLShims_add_sni_context(context, $0, perName) }
                    CHTTPBoringSSL_SSL_CTX_free(perName)  // the registry retains its own reference
                }
                return context
            }
            catch {
                CHTTPBoringSSL_SSL_CTX_free(context)
                throw error
            }
        }

        /// The identity source a context is built from: a PKCS#12 blob (RFC 7292) or PEM texts
        /// (RFC 7468, the G3 intake).
        enum IdentitySource {
            case pkcs12([UInt8], passphrase: String)
            case pem(TransportTLS.PEMIdentity)

            /// The configuration's default identity: PEM when supplied, else the PKCS#12 blob.
            static func from(_ tls: TransportTLS) -> Self {
                if let pem = tls.pemIdentity {
                    return .pem(pem)
                }
                return .pkcs12(tls.pkcs12, passphrase: tls.passphrase)
            }
        }

        /// Builds and configures one server `SSL_CTX` (version, identity, ALPN, client-auth).
        ///
        /// Pins the version range (RFC 8446 / RFC 9325), loads the identity (PKCS#12 or PEM),
        /// installs the ALPN policy (RFC 7301), and sets the client-auth mode (RFC 8446 §4.4.2). The
        /// `verifyPeer` trust hook is applied post-handshake by the connection.
        private static func makeContext(
            identity: IdentitySource, tls: TransportTLS
        ) throws -> OpaquePointer {
            guard let context = CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_server_method())
            else {
                throw TransportError.tlsConfigurationFailed("SSL_CTX_new returned nil")
            }
            do {
                guard
                    CHTTPBoringSSLShims_set_min_proto_version(
                        context, protocolVersion(tls.minVersion)
                    ) == 1,
                    CHTTPBoringSSLShims_set_max_proto_version(
                        context, protocolVersion(tls.maxVersion)
                    ) == 1
                else {
                    throw TransportError.tlsConfigurationFailed(
                        "failed to pin the TLS version range"
                    )
                }
                try load(identity, into: context)
                CHTTPBoringSSLShims_set_alpn_select_h2(context)
                CHTTPBoringSSLShims_set_client_auth(context, clientAuthMode(tls.clientAuth))
                return context
            }
            catch {
                CHTTPBoringSSL_SSL_CTX_free(context)
                throw error
            }
        }

        /// Loads `identity` into `context` — `PKCS12_parse` for a blob, `PEM_read_bio_*` for PEM.
        private static func load(
            _ identity: IdentitySource, into context: OpaquePointer
        ) throws {
            switch identity {
                case .pkcs12(let blob, let passphrase):
                    let loaded = blob.withUnsafeBufferPointer { buffer in
                        CHTTPBoringSSLShims_use_pkcs12(
                            context, buffer.baseAddress, Int32(buffer.count), passphrase
                        )
                    }
                    guard loaded == 1 else {
                        throw TransportError.tlsConfigurationFailed(
                            "failed to load the PKCS#12 identity"
                        )
                    }
                case .pem(let pem):
                    let chain = Array(pem.certificateChainPEM.utf8)
                    let key = Array(pem.privateKeyPEM.utf8)
                    let loaded = chain.withUnsafeBufferPointer { chainBuffer in
                        key.withUnsafeBufferPointer { keyBuffer in
                            CHTTPBoringSSLShims_use_pem(
                                context,
                                chainBuffer.baseAddress,
                                Int32(chainBuffer.count),
                                keyBuffer.baseAddress,
                                Int32(keyBuffer.count)
                            )
                        }
                    }
                    guard loaded == 1 else {
                        throw TransportError.tlsConfigurationFailed(
                            "failed to load the PEM identity (chain + unencrypted key, RFC 7468)"
                        )
                    }
            }
        }

        /// The ALPN-negotiated application protocol of a handshaken `ssl` (RFC 7301), or `nil` when none
        /// was selected.
        static func negotiatedApplicationProtocol(of ssl: OpaquePointer) -> String? {
            var data: UnsafePointer<UInt8>?
            var length: UInt32 = 0
            CHTTPBoringSSL_SSL_get0_alpn_selected(ssl, &data, &length)
            guard let data, length > 0 else {
                return nil
            }
            let bytes = [UInt8](UnsafeBufferPointer(start: data, count: Int(length)))
            return String(decoding: bytes, as: Unicode.UTF8.self)
        }

        /// The peer leaf certificate's Common Name (mutual TLS) on a handshaken `ssl`, or `nil` when no
        /// client certificate was presented — the verified subject surfaced as `tlsPeerSubject`.
        static func peerSubject(of ssl: OpaquePointer) -> String? {
            var buffer = [CChar](repeating: 0, count: 256)
            let length = buffer.withUnsafeMutableBufferPointer {
                CHTTPBoringSSLShims_peer_subject(ssl, $0.baseAddress, Int32($0.count))
            }
            guard length >= 0 else {
                return nil
            }
            let bytes = buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) }
            return String(decoding: bytes, as: Unicode.UTF8.self)
        }

        /// The peer's certificate chain (leaf-first) as raw DER (RFC 5280), or empty when no client
        /// certificate was presented — the backbone-agnostic form the `verifyPeer` trust hook consumes.
        static func peerDERChain(of ssl: OpaquePointer) -> [[UInt8]] {
            final class Accumulator {
                var chain: [[UInt8]] = []

                deinit {
                    // No teardown beyond ARC.
                }
            }
            let accumulator = Accumulator()
            CHTTPBoringSSLShims_peer_der_chain(
                ssl,
                { der, length, context in
                    guard let der, let context else {
                        return
                    }
                    let accumulator = Unmanaged<Accumulator>.fromOpaque(context)
                        .takeUnretainedValue()
                    accumulator.chain.append(
                        [UInt8](UnsafeBufferPointer(start: der, count: Int(length)))
                    )
                },
                Unmanaged.passUnretained(accumulator).toOpaque()
            )
            return accumulator.chain
        }

        /// Maps the backbone-agnostic ``TransportTLS/ClientAuth`` to the shim's mode (0/1/2).
        private static func clientAuthMode(_ clientAuth: TransportTLS.ClientAuth) -> Int32 {
            switch clientAuth {
                case .none:
                    0
                case .optional:
                    1
                case .required:
                    2
            }
        }

        /// Maps a backbone-agnostic ``TLSVersion`` to libssl's protocol-version constant.
        private static func protocolVersion(_ version: TLSVersion) -> Int32 {
            switch version {
                case .tlsV12:
                    Int32(TLS1_2_VERSION)
                case .tlsV13:
                    Int32(TLS1_3_VERSION)
            }
        }
    }

#endif
