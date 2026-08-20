//
//  BoringSSLServerContext.swift
//  HTTPTransport
//
//  Phase 3d — ``PortableTLSServerContext`` on the LEGACY BoringSSL engine
//  (`HTTP_BORINGSSL_TLS`, the temporary A/B gate that dies in 3e): the `SSL_CTX` and the
//  per-connection `SSL`/memory-BIO minting that used to live inline in
//  `PortableTLSTransport.surface(...)`, extracted behind the same two-method seam the
//  HTTPTLS flavor implements — so the transport's start/reload/accept code is engine-blind.
//  Ownership is exactly what it was: the transport calls ``release()`` where it called
//  `SSL_CTX_free` (start-failure paths, the reload swap, accept-loop exit), and each minted
//  `SSL` retains the context it handshakes with, so a reload never frees a context out from
//  under a live connection.
//
//  Standards: TLS 1.3 (RFC 8446); ALPN (RFC 7301); gated with the backbone it serves.
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims

    /// The listener context of the portable TLS backbone on the legacy BoringSSL engine.
    // SAFETY: `@unchecked Sendable` on the same terms as the `ContextBox` it replaces: the
    // one stored property is an immutable `SSL_CTX` pointer, and BoringSSL's `ssl.h`
    // documents the `SSL_CTX` as thread-safe (unlike any `SSL` it mints) — crossing the
    // accept-thread hop with it is exactly what the previous inline code did.
    final class PortableTLSServerContext: @unchecked Sendable {
        /// The shared server `SSL_CTX` — thread-safe per `ssl.h`, unlike any `SSL` it mints.
        private let pointer: OpaquePointer

        /// Builds the `SSL_CTX` from the backbone-agnostic configuration (`OpenSSLTLS`).
        init(_ tls: TransportTLS) throws(TransportError) {
            do {
                pointer = try OpenSSLTLS.serverContext(tls)
            }
            catch let error as TransportError {
                throw error
            }
            catch {
                throw .tlsConfigurationFailed("\(error)")
            }
        }

        deinit {
            // The transport owns the free (``release()``) — never ARC, matching the
            // explicit lifecycle this backbone always had.
        }

        /// Mints one `SSL` over fresh memory BIOs, wrapped as the engine; nil when any
        /// allocation fails (the caller closes the socket and moves on).
        ///
        /// Holds a context reference across `SSL_new` so a concurrent reload's
        /// ``release()`` cannot free the `SSL_CTX` under us; the new `SSL` then retains
        /// the context it handshakes with.
        func makeEngine(connectionID: TransportConnectionID) -> PortableTLSEngine? {
            _ = CHTTPBoringSSL_SSL_CTX_up_ref(pointer)
            let ssl = CHTTPBoringSSL_SSL_new(pointer)
            CHTTPBoringSSL_SSL_CTX_free(pointer)
            guard let ssl else {
                return nil
            }
            // Memory BIOs: SSL reads ciphertext from `readBIO`, writes ciphertext to
            // `writeBIO`; the connection pumps both to/from the non-blocking socket.
            // `SSL_set_bio` transfers ownership (both are freed by `SSL_free`).
            guard let readBIO = CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()),
                let writeBIO = CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem())
            else {
                CHTTPBoringSSL_SSL_free(ssl)
                return nil
            }
            CHTTPBoringSSL_SSL_set_bio(ssl, readBIO, writeBIO)
            return PortableTLSEngine(
                ssl: ssl, readBIO: readBIO, writeBIO: writeBIO, connectionID: connectionID
            )
        }

        /// Releases the transport's reference to the `SSL_CTX`; live `SSL`s keep theirs.
        func release() {
            CHTTPBoringSSL_SSL_CTX_free(pointer)
        }
    }

#endif
