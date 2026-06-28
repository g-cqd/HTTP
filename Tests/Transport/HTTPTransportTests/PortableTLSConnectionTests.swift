//
//  PortableTLSConnectionTests.swift
//  HTTPTransportTests
//
//  Phase 2 of the portable TLS backbone (ADR 0004): proves the production byte bridge —
//  `OpenSSLTLS.serverContext` + `PortableTLSConnection` carry a real TLS 1.3 session over an accepted
//  socket and round-trip plaintext. A `socketpair` stands in for an accepted connection; the server
//  side is a `PortableTLSConnection` (its `performHandshake`/`receive`/`send`/`close` drive libssl),
//  the client side is a raw libssl peer on a background queue. The gate mirrors the other backbones'
//  `assertLoopbackEcho`: send `ping`, read it back unchanged — but end-to-end through TLS.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — runs only in the opt-in portable build (`HTTP_PORTABLE_TLS`).
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Dispatch
    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS (vendored BoringSSL) — Phase 2 connection (ADR 0004)")
    struct PortableTLSConnectionTests {
        @Test(
            "a TLS session round-trips plaintext through PortableTLSConnection over a socket",
            .timeLimit(.minutes(1)))
        func connectionEchoesOverLoopback() async throws {
            let identity = try DevTLSIdentity.selfSigned()
            let serverContext = try OpenSSLTLS.serverContext(identity)
            defer { CHTTPBoringSSL_SSL_CTX_free(serverContext) }

            var descriptors = [Int32](repeating: 0, count: 2)
            let paired = descriptors.withUnsafeMutableBufferPointer { buffer in
                #if canImport(Darwin)
                    socketpair(AF_UNIX, SOCK_STREAM, 0, buffer.baseAddress)
                #else
                    socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, buffer.baseAddress)
                #endif
            }
            #expect(paired == 0)
            let serverDescriptor = descriptors[0]
            let clientDescriptor = descriptors[1]

            // Server side: wrap the accepted descriptor in a PortableTLSConnection.
            let serverSSL = try #require(CHTTPBoringSSL_SSL_new(serverContext))
            CHTTPBoringSSL_SSL_set_fd(serverSSL, serverDescriptor)
            let connection = PortableTLSConnection(
                id: TransportConnectionID(1),
                peer: TransportAddress(host: "127.0.0.1", port: 0),
                ssl: serverSSL,
                descriptor: serverDescriptor,
                clientAuth: .none,
                verifyPeer: nil
            )

            // Client side: a raw libssl peer that handshakes, sends "ping", and records the echo it reads.
            let clientContext = try #require(
                CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method()))
            // Trust the dev self-signed leaf (test only).
            CHTTPBoringSSL_SSL_CTX_set_verify(clientContext, SSL_VERIFY_NONE, nil)
            #expect(CHTTPBoringSSLShims_set_client_alpn(clientContext) == 0)
            // `SSL` access is confined to the single background closure below, so the non-Sendable
            // `OpaquePointer` is safe to hand it — `nonisolated(unsafe)` states that invariant.
            nonisolated(unsafe) let clientSSL = try #require(CHTTPBoringSSL_SSL_new(clientContext))
            CHTTPBoringSSL_SSL_set_fd(clientSSL, clientDescriptor)
            let echoed = AsyncEventProbe<[UInt8]>()
            DispatchQueue.global()
                .async {
                    guard CHTTPBoringSSL_SSL_connect(clientSSL) == 1 else {
                        return
                    }
                    let ping = [UInt8]("ping".utf8)
                    _ = ping.withUnsafeBytes {
                        CHTTPBoringSSL_SSL_write(clientSSL, $0.baseAddress, Int32($0.count))
                    }
                    var buffer = [UInt8](repeating: 0, count: 64)
                    let count = buffer.withUnsafeMutableBytes {
                        CHTTPBoringSSL_SSL_read(clientSSL, $0.baseAddress, Int32($0.count))
                    }
                    if count > 0 {
                        buffer.removeLast(buffer.count - Int(count))
                        echoed.record(buffer)
                    }
                }
            defer {
                CHTTPBoringSSL_SSL_free(clientSSL)
                CHTTPBoringSSL_SSL_CTX_free(clientContext)
                _ = close(clientDescriptor)
            }

            // Server drives the handshake, reads the request, echoes it.
            try await connection.performHandshake()
            let received = try await connection.receive(maxLength: 64)
            #expect(received == [UInt8]("ping".utf8))
            try await connection.send(try #require(received))

            let echoes = try await echoed.wait(forAtLeast: 1, timeout: .seconds(15))
            #expect(echoes.first == [UInt8]("ping".utf8))
            #expect(connection.isSecure)
            await connection.close()
        }
    }

#endif
