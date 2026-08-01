//
//  PortableTLSReceiveResidencyTests.swift
//  HTTPTransportTests
//
//  ADD-P2 for the TLS backbone, which the addendum singles out as carrying "roughly another 32 KiB of
//  user buffer state after activation". Both halves are claimed here now:
//
//  - The PLAINTEXT scratch `SSL_read` decrypts into, which used to be sized to the caller's `maxLength`
//    on the first read and held for the connection's life.
//  - The CIPHERTEXT pump, which used to be a single 16 KiB array allocated in a property initializer —
//    before the handshake, whether or not the connection ever moved a byte — and shared between the
//    ingress and egress pumps. The sharing was the concurrency defect; splitting it settled the
//    residency question too. The ingress half is now an adaptive `ReceiveScratch` like the plaintext
//    one, and the egress half is staged on first flush at the size the records actually need.
//
//  The oracles are `receiveScratchBytes` and `ciphertextScratchBytes` — the octets each side actually
//  holds, which is what allocation *counting* cannot see. A real TLS 1.3 session over a socket pair,
//  read at the same 16 KiB ceiling the HTTP/1 request reader passes.
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

            #expect(
                connection.ciphertextScratchBytes == 0,
                "a constructed connection must hold no pump buffer at all — this was 16,384"
            )
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
            // And the pump, which is now TWO buffers, still holds less than the ONE it replaced: the
            // ingress floor plus an egress stage sized to the handshake flight (~3.3 KiB together on
            // this identity). A bound rather than a figure, because the flight's size follows the
            // certificate's DER length, which `DevTLSIdentity.selfSigned()` does not fix.
            #expect(connection.ciphertextScratchBytes >= ReceiveScratch.floorWindow)
            #expect(connection.ciphertextScratchBytes < 16_384)

            await connection.close()
        }

        @Test(
            "constructing a connection allocates no ciphertext pump buffer at all",
            .timeLimit(.minutes(1)))
        func constructionAllocatesNoPumpBuffer() throws {
            let identity = try DevTLSIdentity.selfSigned()
            let serverContext = try OpenSSLTLS.serverContext(identity)
            defer { CHTTPBoringSSL_SSL_CTX_free(serverContext) }
            let loop = try TLSEventLoop()
            loop.start()
            defer { loop.stop() }

            // Warm up outside the window: the first construction pays one-time lazy initialization
            // that has nothing to do with the buffer under test (see `mallocDelta`'s contract).
            _ = try Self.makeIdleConnection(serverContext, loop: loop)
            let session = try Self.makeSession(serverContext)
            var built: PortableTLSConnection?
            let octets = mallocByteDelta {
                built = PortableTLSConnection(
                    id: TransportConnectionID(2),
                    peer: TransportAddress(host: "127.0.0.1", port: 0),
                    ssl: session.ssl,
                    readBIO: session.readBIO,
                    writeBIO: session.writeBIO,
                    descriptor: -1,
                    eventLoop: loop,
                    clientAuth: .none,
                    verifyPeer: nil
                )
            }
            // The residency oracle first: counting cannot see how large an allocation was, so this is
            // the claim, and the octet measurement below is the corroboration.
            #expect(built?.ciphertextScratchBytes == 0)
            #expect(built?.receiveScratchBytes == 0)
            guard let octets else {
                return  // allocation counting is Darwin-only; the residency oracle above still ran
            }
            // The initializer used to allocate a 16,384-octet array here, before the handshake and
            // whether or not the connection ever moved a byte. A ceiling far below that rather than a
            // figure: debug charges phantom allocations per `Array.append`, so only the DIRECTION of
            // this comparison is build-invariant — and the direction is the whole claim.
            #expect(octets < 16_384)
        }

        /// An `SSL` with its two memory BIOs, built outside an allocation measurement window.
        private static func makeSession(
            _ context: OpaquePointer
        ) throws -> (
            ssl: OpaquePointer, readBIO: UnsafeMutablePointer<BIO>,
            writeBIO: UnsafeMutablePointer<BIO>
        ) {
            let ssl = try #require(CHTTPBoringSSL_SSL_new(context))
            let readBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            let writeBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            CHTTPBoringSSL_SSL_set_bio(ssl, readBIO, writeBIO)
            return (ssl, readBIO, writeBIO)
        }

        /// A connection over a descriptor it never touches — the warm-up subject.
        private static func makeIdleConnection(
            _ context: OpaquePointer,
            loop: TLSEventLoop
        ) throws -> PortableTLSConnection {
            let session = try Self.makeSession(context)
            return PortableTLSConnection(
                id: TransportConnectionID(3),
                peer: TransportAddress(host: "127.0.0.1", port: 0),
                ssl: session.ssl,
                readBIO: session.readBIO,
                writeBIO: session.writeBIO,
                descriptor: -1,
                eventLoop: loop,
                clientAuth: .none,
                verifyPeer: nil
            )
        }
    }

#endif
