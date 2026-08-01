//
//  PortableTLSReceiveResidencyTests.swift
//  HTTPTransportTests
//
//  ADD-P2 for the TLS backbone, which the addendum singles out as carrying "roughly another 32 KiB of
//  user buffer state after activation". Two of those buffers exist: the PLAINTEXT scratch `SSL_read`
//  decrypts into, which used to be sized to the caller's `maxLength` on the first read and held for
//  the connection's life, and the CIPHERTEXT pump buffer, which is allocated at 16 KiB in the property
//  initializer and is NOT touched here — it is shared between the ingress and egress pumps, so
//  resizing it is entangled with a separate question about whether that sharing is safe under
//  concurrent send/receive. Only the plaintext half is claimed.
//
//  The oracle is `receiveScratchBytes` — the octets the plaintext scratch actually holds. A real TLS
//  1.3 session over a socket pair, read at the same 16 KiB ceiling the HTTP/1 request reader passes.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — runs only in the opt-in portable build
//  (`HTTP_PORTABLE_TLS`), like every other PortableTLS suite.
//
//  Standards: TLS 1.3 (RFC 8446) over a POSIX.1-2017 (IEEE Std 1003.1-2017) socket pair.
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

    @Suite("Portable TLS — plaintext receive residency (ADD-P2)", .realNetwork)
    struct PortableTLSReceiveResidencyTests {
        /// The ceiling `HTTPServer+RequestReader` passes on every HTTP/1 read.
        private static let serverCeiling = 16_384

        /// A minimal but realistic HTTP/1.1 request head — the read this finding is about.
        private static let requestHead = Array(
            "GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: probe/1\r\n\r\n".utf8
        )

        @Test(
            "an ordinary request over TLS leaves the floor resident, not the 16 KiB ceiling",
            .timeLimit(.minutes(1)))
        func anOrdinaryRequestHoldsOnlyTheFloor() async throws {
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

            POSIXSocket.setNonBlocking(serverDescriptor)
            let serverSSL = try #require(CHTTPBoringSSL_SSL_new(serverContext))
            let readBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            let writeBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            CHTTPBoringSSL_SSL_set_bio(serverSSL, readBIO, writeBIO)
            let loop = try TLSEventLoop()
            loop.start()
            defer { loop.stop() }
            let connection = PortableTLSConnection(
                id: TransportConnectionID(1),
                peer: TransportAddress(host: "127.0.0.1", port: 0),
                ssl: serverSSL,
                readBIO: readBIO,
                writeBIO: writeBIO,
                descriptor: serverDescriptor,
                eventLoop: loop,
                clientAuth: .none,
                verifyPeer: nil
            )

            // Client side: a raw libssl peer that handshakes and writes one ordinary request head.
            let clientContext = try #require(
                CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method()))
            CHTTPBoringSSL_SSL_CTX_set_verify(clientContext, SSL_VERIFY_NONE, nil)
            #expect(CHTTPBoringSSLShims_set_client_alpn(clientContext) == 0)
            // `SSL` access is confined to the single background closure below, so the non-Sendable
            // `OpaquePointer` is safe to hand it — `nonisolated(unsafe)` states that invariant.
            nonisolated(unsafe) let clientSSL = try #require(CHTTPBoringSSL_SSL_new(clientContext))
            CHTTPBoringSSL_SSL_set_fd(clientSSL, clientDescriptor)
            let head = Self.requestHead
            DispatchQueue.global()
                .async {
                    guard CHTTPBoringSSL_SSL_connect(clientSSL) == 1 else {
                        return
                    }
                    _ = head.withUnsafeBytes {
                        CHTTPBoringSSL_SSL_write(clientSSL, $0.baseAddress, Int32($0.count))
                    }
                }
            defer {
                CHTTPBoringSSL_SSL_free(clientSSL)
                CHTTPBoringSSL_SSL_CTX_free(clientContext)
                _ = close(clientDescriptor)
            }

            try await connection.performHandshake()
            #expect(
                connection.receiveScratchBytes == 0,
                "the handshake alone must not size the plaintext scratch"
            )

            var buffer: [UInt8] = []
            while buffer.count < head.count {
                let count = try await connection.receive(
                    into: &buffer,
                    maxLength: Self.serverCeiling
                )
                guard count > 0 else {
                    break
                }
            }
            #expect(buffer == head)
            // BEFORE this change the same read left 16,384 octets of plaintext scratch resident for
            // the connection's life, on top of the 16 KiB ciphertext pump buffer.
            #expect(connection.receiveScratchBytes == ReceiveScratch.floorWindow)

            await connection.close()
        }
    }

#endif
