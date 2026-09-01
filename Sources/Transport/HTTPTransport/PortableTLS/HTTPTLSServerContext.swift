//
//  HTTPTLSServerContext.swift
//  HTTPTransport
//
//  Phase 3d — ``PortableTLSServerContext`` on the HTTPTLS engine: the listener-scoped half
//  the transport swaps on ``PortableTLSTransport/reload(tls:)``, mirroring what an
//  `SSL_CTX` was to the BoringSSL flavor. It holds the intake's negotiation contract and
//  the identity store, and mints one ``PortableTLSEngine`` per accepted connection. Where
//  the BoringSSL flavor needed manual reference counting (`SSL_CTX_up_ref`/`free`) and an
//  explicit ``release()``, this one is plain ARC over `Sendable` values; `release()` stays
//  on the surface so the transport treats both flavors identically and the 3e deletion of
//  the legacy flavor removes dead weight, not a seam.
//
//  The type name matches the BoringSSL flavor's on purpose — build-exclusive gates, one
//  compiled flavor per build (see `HTTPTLSEngine.swift`).
//

#if HTTP_PORTABLE_TLS_SWIFT

    internal import HTTPTLS

    /// The listener context of the portable TLS backbone on the HTTPTLS engine.
    final class PortableTLSServerContext: Sendable {
        /// The per-connection negotiation contract built by ``HTTPTLSIntake``.
        private let configuration: TLSServerConfiguration
        /// The listener's identity store (RFC 6066 SNI catalog inside).
        private let identities: TLSIdentityStore

        /// Builds a context from the backbone-agnostic configuration, failing closed on
        /// anything the engine does not serve (see ``HTTPTLSIntake``).
        init(_ tls: TransportTLS) throws(TransportError) {
            let parameters = try HTTPTLSIntake.serverParameters(tls)
            configuration = parameters.configuration
            identities = parameters.identities
        }

        deinit {
            // No teardown beyond ARC.
        }

        /// Mints the engine for one accepted connection.
        ///
        /// Never nil on this flavor — the optional is the BoringSSL flavor's
        /// allocation-failure shape, kept for parity.
        func makeEngine(connectionID: TransportConnectionID) -> PortableTLSEngine? {
            PortableTLSEngine(
                connection: TLSServerConnection(
                    configuration: configuration, identitySelector: identities
                ),
                connectionID: connectionID
            )
        }

        /// Surface parity with the BoringSSL flavor's `SSL_CTX_free` — ARC owns this one.
        func release() {
            // Nothing to free.
        }
    }

#endif
