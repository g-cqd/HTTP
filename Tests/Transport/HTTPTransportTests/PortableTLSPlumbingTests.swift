//
//  PortableTLSPlumbingTests.swift
//  HTTPTransportTests
//
//  Phase 1 of the portable TLS backbone (ADR 0004): proves the SwiftPM ⇄ system-OpenSSL plumbing
//  end-to-end — the `CHTTPBoringSSL` shim links and imports, the macro-wrapping helper functions are
//  callable, and a real TLS 1.3 handshake negotiates ALPN `h2` over memory BIOs (the socket-free form
//  of the bridge the production connection will use). The server identity is a `DevTLSIdentity`
//  PKCS#12 parsed straight into the `SSL_CTX` — no keychain, no prompts (the portability win).
//
//  The whole file is gated `#if canImport(CHTTPBoringSSL)`, so it compiles to nothing unless the build
//  opted into the portable backbone with `HTTP_PORTABLE_TLS=1` — the default apple-only build and CI
//  are unaffected.
//

#if canImport(CHTTPBoringSSL)

    import CHTTPBoringSSL
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS (system OpenSSL) — Phase 1 plumbing (ADR 0004)")
    struct PortableTLSPlumbingTests {
        @Test("the CHTTPBoringSSL shim links system OpenSSL and its macro wrappers are callable")
        func shimLinksAndImports() throws {
            let context = try #require(SSL_CTX_new(TLS_server_method()))
            defer { SSL_CTX_free(context) }
            #expect(CHTTPBoringSSL_set_min_proto_version(context, Int32(TLS1_3_VERSION)) == 1)
            #expect(CHTTPBoringSSL_set_max_proto_version(context, Int32(TLS1_3_VERSION)) == 1)
        }

        @Test("a TLS 1.3 handshake completes and negotiates ALPN h2 over memory BIOs")
        func handshakeNegotiatesTLS13AndALPNh2() throws {
            let identity = try DevTLSIdentity.selfSigned()

            let server = try #require(SSL_CTX_new(TLS_server_method()))
            defer { SSL_CTX_free(server) }
            #expect(CHTTPBoringSSL_set_min_proto_version(server, Int32(TLS1_3_VERSION)) == 1)
            #expect(CHTTPBoringSSL_set_max_proto_version(server, Int32(TLS1_3_VERSION)) == 1)
            let loaded = identity.pkcs12.withUnsafeBufferPointer { buffer in
                CHTTPBoringSSL_use_pkcs12(
                    server, buffer.baseAddress, Int32(buffer.count), identity.passphrase
                )
            }
            #expect(loaded == 1)
            CHTTPBoringSSL_set_alpn_select_h2(server)

            let client = try #require(SSL_CTX_new(TLS_client_method()))
            defer { SSL_CTX_free(client) }
            #expect(CHTTPBoringSSL_set_min_proto_version(client, Int32(TLS1_3_VERSION)) == 1)
            // The test trusts the dev self-signed leaf, so the client skips chain verification.
            SSL_CTX_set_verify(client, SSL_VERIFY_NONE, nil)
            #expect(CHTTPBoringSSL_set_client_alpn(client) == 0)  // OpenSSL: 0 == success here

            let serverSSL = try #require(SSL_new(server))
            defer { SSL_free(serverSSL) }
            let clientSSL = try #require(SSL_new(client))
            defer { SSL_free(clientSSL) }
            // `SSL_set_bio` takes ownership of both BIOs, so `SSL_free` releases them — no separate frees.
            // `BIO_new` is imported non-optional (never returns nil), so it needs no `#require`.
            SSL_set_bio(serverSSL, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()))
            SSL_set_bio(clientSSL, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()))
            SSL_set_accept_state(serverSSL)
            SSL_set_connect_state(clientSSL)

            #expect(CHTTPBoringSSL_handshake(serverSSL, clientSSL) == 1)

            #expect(String(cString: SSL_get_version(serverSSL)) == "TLSv1.3")
            #expect(Self.negotiatedALPN(of: serverSSL) == "h2")
            #expect(Self.negotiatedALPN(of: clientSSL) == "h2")
        }

        /// The ALPN protocol the handshake settled on (RFC 7301), or `nil` if none was negotiated.
        private static func negotiatedALPN(of ssl: OpaquePointer) -> String? {
            var data: UnsafePointer<UInt8>?
            var length: UInt32 = 0
            SSL_get0_alpn_selected(ssl, &data, &length)
            guard let data, length > 0 else {
                return nil
            }
            let bytes = [UInt8](UnsafeBufferPointer(start: data, count: Int(length)))
            return String(decoding: bytes, as: Unicode.UTF8.self)
        }
    }

#endif
