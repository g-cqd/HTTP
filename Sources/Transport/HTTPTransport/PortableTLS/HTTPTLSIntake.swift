//
//  HTTPTLSIntake.swift
//  HTTPTransport
//
//  Phase 3d — the single place the portable TLS backbone maps the backbone-agnostic
//  `TransportTLS` onto the HTTPTLS engine's configuration surface: the successor to
//  `OpenSSLTLS.serverContext` on the pure-Swift engine. Identities become
//  ``TLSCertificateIdentity`` (PEM chain + key; RSA keys route through `HTTPTLSRSA`'s
//  signer), the SNI map becomes a ``TLSIdentityCatalog`` inside a ``TLSIdentityStore``
//  (the reload contract), and client auth maps mode-for-mode. The `verifyPeer` hook stays
//  where the backbone has always applied it — post-handshake, in the connection's
//  fail-closed table — so the engine's own chain validator is deliberately NOT wired here.
//
//  PKCS#12 (RFC 7292) is NOT parsed on this engine — the recorded 3d decision. Reading the
//  common blobs takes RC2/3DES/PBES1 legacy cryptography (or a platform parser that Linux
//  does not have), and shipping either in a from-scratch TLS stack to support a packaging
//  format is scope this project refuses: convert ONCE at deployment
//  (`openssl pkcs12 -nodes`) and hand the backbone PEM, or use the Network backbone, whose
//  Security-framework intake is PKCS#12-native. A PKCS#12-only configuration fails closed
//  with a typed error that says exactly that.
//
//  Standards: TLS 1.3 (RFC 8446); PEM (RFC 7468); ALPN (RFC 7301); SNI (RFC 6066 §3);
//  session tickets (RFC 8446 §4.6.1) sealed by a per-context ``TLSStatelessTicketVault``.
//

#if HTTP_PORTABLE_TLS_SWIFT

    internal import Crypto
    internal import HTTPTLS
    internal import HTTPTLSRSA

    /// Maps `TransportTLS` onto the HTTPTLS engine's configuration + identity store.
    enum HTTPTLSIntake {
        /// The engine-side parameters for one listener context.
        struct ServerParameters {
            /// The per-connection negotiation contract.
            let configuration: TLSServerConfiguration
            /// The listener's identity store (SNI catalog inside; reload swaps it).
            let identities: TLSIdentityStore
        }

        /// Builds the engine parameters, failing closed on anything this engine does not
        /// serve: PKCS#12 identities, a TLS 1.2 ceiling, undecodable PEM.
        static func serverParameters(
            _ tls: TransportTLS
        ) throws(TransportError) -> ServerParameters {
            guard tls.maxVersion == .tlsV13 else {
                // The engine is TLS 1.3-only by construction (no 1.2, ADR 0004 Phase 3a);
                // a 1.3-excluding ceiling cannot be served — fail at bind, not per client.
                throw .tlsConfigurationFailed(
                    "the portable TLS engine is TLS 1.3-only; maxVersion excludes it"
                )
            }
            let identity = try makeIdentity(of: tls)
            var sniIdentities: [String: any TLSIdentityProvider] = [:]
            for (name, sni) in tls.sniIdentities {
                guard let pem = sni.pem else {
                    throw pkcs12Unsupported(context: "the SNI identity for \(name)")
                }
                sniIdentities[name] = try makeIdentity(pem: pem)
            }
            var configuration = TLSServerConfiguration()
            configuration.alpnProtocols = tls.applicationProtocols
            configuration.clientAuthentication = clientAuthenticationMode(tls.clientAuth)
            // RSA-PSS widening over the ECDSA/Ed25519 default: every dev identity — and
            // most real client certificates — is RSA, and a verifier that cannot read them
            // would fail closed on chains the old engine accepted.
            configuration.certificateVerifier = TLSRSACertificateVerifier()
            // §4.6.1 tickets under a fresh per-context key: same session scope as the old
            // engine's per-`SSL_CTX` ticket keys — a reload rotates them, by design.
            configuration.ticketVault = makeTicketVault()
            return ServerParameters(
                configuration: configuration,
                identities: TLSIdentityStore(
                    TLSIdentityCatalog(
                        defaultIdentity: identity, sniIdentities: sniIdentities
                    )
                )
            )
        }

        // MARK: - Internals

        /// The default identity: PEM only — PKCS#12 fails closed with the conversion note.
        private static func makeIdentity(
            of tls: TransportTLS
        ) throws(TransportError) -> any TLSIdentityProvider {
            guard let pem = tls.pemIdentity else {
                throw pkcs12Unsupported(context: "the default identity")
            }
            return try makeIdentity(pem: pem)
        }

        /// One PEM identity → ``TLSCertificateIdentity``, with RSA keys routed through
        /// `HTTPTLSRSA` (the engine's native signers are ECDSA P-256/384/521 + Ed25519).
        private static func makeIdentity(
            pem: TransportTLS.PEMIdentity
        ) throws(TransportError) -> any TLSIdentityProvider {
            do {
                return try TLSCertificateIdentity(
                    certificateChainPEM: pem.certificateChainPEM,
                    privateKeyPEM: pem.privateKeyPEM
                )
            }
            catch .rsaKeyRequiresRSASigner {
                do {
                    return try TLSCertificateIdentity(
                        certificateChainPEM: pem.certificateChainPEM,
                        signer: TLSRSAIdentitySigner(privateKeyPEM: pem.privateKeyPEM)
                    )
                }
                catch {
                    throw .tlsConfigurationFailed("PEM identity rejected: \(error)")
                }
            }
            catch {
                // Load-time §4.4.2 validation names the defect (order, key mismatch, PEM
                // shape) — surface it verbatim; a misconfigured listener dies at bind.
                throw .tlsConfigurationFailed("PEM identity rejected: \(error)")
            }
        }

        /// The recorded PKCS#12 decision, as a typed error with the way out.
        private static func pkcs12Unsupported(context: String) -> TransportError {
            .tlsConfigurationFailed(
                "\(context) is PKCS#12, which the pure-Swift portable TLS engine does not "
                    + "parse — convert once at deployment (openssl pkcs12 -nodes) and supply "
                    + "PEM, or use the Network backbone"
            )
        }

        /// Mode-for-mode: the engine's semantics were specified FROM this backbone's
        /// fail-closed table (see `TLSClientAuthenticationMode`).
        private static func clientAuthenticationMode(
            _ clientAuth: TransportTLS.ClientAuth
        ) -> TLSClientAuthenticationMode {
            switch clientAuth {
                case .none:
                    .none
                case .optional:
                    .optional
                case .required:
                    .required
            }
        }

        /// A fresh single-key vault: 8 random name octets (public) + a 256-bit secret.
        private static func makeTicketVault() -> (any TLSTicketVault)? {
            var generator = SystemRandomNumberGenerator()
            let name = (0 ..< TLSTicketKey.nameLength)
                .map { _ in
                    UInt8.random(in: .min ... .max, using: &generator)
                }
            guard let key = TLSTicketKey(name: name, secret: SymmetricKey(size: .bits256))
            else {
                return nil  // unreachable by shape; tickets would simply not be offered
            }
            return TLSStatelessTicketVault(keys: [key])
        }
    }

#endif
