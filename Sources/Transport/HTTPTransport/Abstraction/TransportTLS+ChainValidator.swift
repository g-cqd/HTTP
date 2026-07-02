//
//  TransportTLS+ChainValidator.swift
//  HTTPTransport
//
//  The trust-roots seam for mutual TLS (G3): a factory building a ``TransportTLS/verifyPeer`` hook
//  from a fixed set of root-CA certificates — "the presented chain must validate to one of these
//  CAs" (RFC 5280 §6 path validation) — so a downstream expresses the common CA policy in one line
//  instead of hand-rolling chain validation. Implemented by the platform's validator: Security
//  (`SecTrust`) on Darwin, BoringSSL (`X509_STORE`) on the portable backbone; absent (by compile-time
//  omission, not a stub) on a platform with neither, which also has no TLS backbone to hook.
//

#if canImport(Security) || canImport(CHTTPBoringSSLShims)

    extension TransportTLS {
        /// Builds a ``verifyPeer`` hook that accepts a presented client-certificate chain only when
        /// it validates to one of `roots` (each a DER-encoded CA certificate) — X.509 path
        /// validation per RFC 5280 §6: chain building, signature verification, and validity windows,
        /// with the anchor set pinned to exactly `roots` (the platform trust store is not consulted).
        ///
        /// Fails closed: an empty chain, an empty `roots`, an undecodable certificate, or any
        /// validation failure rejects the handshake. Use it as the ``verifyPeer`` of a
        /// ``ClientAuth/required`` / ``ClientAuth/optional`` listener:
        ///
        /// ```swift
        /// TransportTLS(
        ///     pkcs12: identity, passphrase: "…",
        ///     clientAuth: .required,
        ///     verifyPeer: TransportTLS.chainValidator(roots: [caDER])
        /// )
        /// ```
        ///
        /// No end-entity semantics beyond the path are checked (no host name — a client certificate
        /// names no host — and no extended-key-usage policy); compose a stricter hook on top when an
        /// application needs them, e.g. by also matching the leaf's SANs from
        /// ``TLSPeerIdentity/subjectAlternativeNames``.
        public static func chainValidator(roots: [[UInt8]]) -> @Sendable ([[UInt8]]) -> Bool {
            #if canImport(Security)
                SecurityChainValidator.validator(roots: roots)
            #else
                BoringSSLChainValidator.validator(roots: roots)
            #endif
        }
    }

#endif
