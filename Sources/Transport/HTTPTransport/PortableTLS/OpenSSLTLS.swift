//
//  OpenSSLTLS.swift
//  HTTPTransport
//
//  The single place the portable TLS backbone touches the libssl `SSL_CTX` surface — the mirror of
//  `NetworkFrameworkTLS` for the Network backbone (ADR 0004). Builds a server `SSL_CTX` from the
//  backbone-agnostic `TransportTLS` (the same PKCS#12 identity + ALPN + version policy the Network
//  path uses), and reads handshake metadata. All libssl calls go through the `CHTTPBoringSSL` shim,
//  so the unsafe interop stays bounded here; every entry point fails closed to a typed
//  `TransportError`.
//
//  Gated `#if canImport(CHTTPBoringSSL)` — present only in the opt-in portable build (`HTTP_PORTABLE_TLS`).
//
//  Standards: TLS 1.3 (RFC 8446 / RFC 9325 floor); ALPN (RFC 7301) selects "h2"/"http/1.1"; PKCS#12
//  identities (RFC 7292).
//

#if canImport(CHTTPBoringSSL)

    internal import CHTTPBoringSSL

    /// Safe Swift wrappers over the libssl `SSL_CTX` configuration used by the portable backbone.
    enum OpenSSLTLS {
        /// Builds a server `SSL_CTX` from `tls` — version range, PKCS#12 identity, and ALPN policy.
        ///
        /// Pins the TLS version range (RFC 8446 / RFC 9325; default TLS 1.3-only), loads the PKCS#12
        /// server identity, and installs the ALPN selection policy (RFC 7301). The caller owns the
        /// returned context and must `SSL_CTX_free` it once no live `SSL` references it (an `SSL` retains
        /// its context, so it may be freed after the last `SSL_new`).
        ///
        /// Client-auth (`.none`/`.optional`/`.required` + `verifyPeer`) and SNI multi-cert land in later
        /// phases; this phase is one-way server TLS.
        static func serverContext(_ tls: TransportTLS) throws -> OpaquePointer {
            guard let context = SSL_CTX_new(TLS_server_method()) else {
                throw TransportError.tlsConfigurationFailed("SSL_CTX_new returned nil")
            }
            do {
                guard
                    CHTTPBoringSSL_set_min_proto_version(context, protocolVersion(tls.minVersion))
                        == 1,
                    CHTTPBoringSSL_set_max_proto_version(context, protocolVersion(tls.maxVersion))
                        == 1
                else {
                    throw TransportError.tlsConfigurationFailed(
                        "failed to pin the TLS version range"
                    )
                }
                let loaded = tls.pkcs12.withUnsafeBufferPointer { buffer in
                    CHTTPBoringSSL_use_pkcs12(
                        context, buffer.baseAddress, Int32(buffer.count), tls.passphrase
                    )
                }
                guard loaded == 1 else {
                    throw TransportError.tlsConfigurationFailed(
                        "failed to load the PKCS#12 identity"
                    )
                }
                CHTTPBoringSSL_set_alpn_select_h2(context)
                return context
            }
            catch {
                SSL_CTX_free(context)
                throw error
            }
        }

        /// The ALPN-negotiated application protocol of a handshaken `ssl` (RFC 7301), or `nil` when none
        /// was selected.
        static func negotiatedApplicationProtocol(of ssl: OpaquePointer) -> String? {
            var data: UnsafePointer<UInt8>?
            var length: UInt32 = 0
            SSL_get0_alpn_selected(ssl, &data, &length)
            guard let data, length > 0 else {
                return nil
            }
            let bytes = [UInt8](UnsafeBufferPointer(start: data, count: Int(length)))
            return String(decoding: bytes, as: Unicode.UTF8.self)
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
