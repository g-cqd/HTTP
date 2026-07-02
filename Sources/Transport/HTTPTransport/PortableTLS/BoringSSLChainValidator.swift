//
//  BoringSSLChainValidator.swift
//  HTTPTransport
//
//  The portable-backbone implementation of the trust-roots `verifyPeer` seam (G3): X.509 path
//  validation (RFC 5280 §6) of a presented client-certificate chain against a fixed set of root CAs,
//  via BoringSSL's `X509_STORE` / `X509_verify_cert` behind the C shims. Anchors are exactly the
//  given roots (no system store). Runs once per handshake, never on the byte path — building the
//  store per call keeps the closure state-free and `Sendable` for free.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` (the opt-in `HTTP_PORTABLE_TLS` build) — the Darwin
//  `SecTrust` twin covers the Network backbone.
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSLShims

    /// Validates presented DER chains against pinned root CAs with BoringSSL (RFC 5280 §6).
    enum BoringSSLChainValidator {
        /// A `verifyPeer` hook accepting only chains that validate to one of `roots` (DER).
        ///
        /// Fails closed: an empty chain, an empty `roots`, an undecodable certificate, or any
        /// validation failure is a rejection.
        static func validator(roots: [[UInt8]]) -> @Sendable ([[UInt8]]) -> Bool {
            { chainDER in
                guard !chainDER.isEmpty, !roots.isEmpty else {
                    return false
                }
                guard let store = CHTTPBoringSSLShims_trust_store_create() else {
                    return false
                }
                defer { CHTTPBoringSSLShims_trust_store_free(store) }
                for root in roots {
                    let added = root.withUnsafeBufferPointer {
                        CHTTPBoringSSLShims_trust_store_add_root(
                            store, $0.baseAddress, Int32($0.count)
                        )
                    }
                    guard added == 1 else {
                        return false
                    }
                }
                guard let chain = CHTTPBoringSSLShims_chain_create() else {
                    return false
                }
                defer { CHTTPBoringSSLShims_chain_free(chain) }
                for certificate in chainDER {
                    let appended = certificate.withUnsafeBufferPointer {
                        CHTTPBoringSSLShims_chain_append(chain, $0.baseAddress, Int32($0.count))
                    }
                    guard appended == 1 else {
                        return false
                    }
                }
                return CHTTPBoringSSLShims_trust_store_validate(store, chain) == 1
            }
        }
    }

#endif
