//
//  PortableTLSSerializationTests.swift
//  HTTPTransportTests
//
//  A `PortableTLSConnection` is driven by two tasks on every HTTP/2 connection and every HTTP/1
//  WebSocket session: a continuous reader and a sole writer. Both drive the same `SSL`, the same two
//  memory BIOs and the same ciphertext buffers, so the record stream they produce must survive that.
//
//  The interleaving here is forced, not hoped for. The socket pair's buffers are shrunk to a few KiB
//  and the client deliberately stops reading, so a large `send` is *guaranteed* to park mid-drain with
//  ciphertext staged; the client then writes one record into that window, which — before this change —
//  the ingress pump read straight over the egress pump's staging buffer, because they were the same
//  16 KiB array. The parked writer then resumed and put the peer's own ciphertext on the wire in place
//  of its records. Verified by mutation: reinstating the shared buffer fails this test on every run.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — the opt-in portable build (`HTTP_PORTABLE_TLS`).
//
//  Standards: TLS 1.3 (RFC 8446) — §5.1 requires records to arrive in the order they were produced
//  over a reliable transport, and a spliced record stream fails its AEAD tag (§5.2). CWE-362 (race on
//  a shared resource); CWE-663 (reentrant use of a non-reentrant `SSL`).
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

    @Suite("Portable TLS — engine serialization under a concurrent reader and writer", .realNetwork)
    struct PortableTLSSerializationTests {
        /// The server's SEND window.
        ///
        /// Small enough that a multi-record send is certain to park on writability part-way through a
        /// staged chunk, large enough that the handshake still fits.
        private static let sendBuffer: Int32 = 2_048

        /// The server's RECEIVE window, deliberately much larger than ``sendBuffer``.
        ///
        /// This asymmetry is what makes the corruption observable rather than merely present: the
        /// ingress pump must be able to read MORE octets in one `read(2)` than the egress pump has
        /// already put on the wire, or its overwrite lands entirely on octets that have already left
        /// and nothing detectable reaches the peer.
        private static let receiveBuffer: Int32 = 256 * 1_024

        /// Comfortably more than the socket buffers and more than one TLS record, so the drain parks
        /// with ciphertext staged rather than completing in one write.
        private static let payloadOctets = 256 * 1_024

        /// What the client sends into the writer's parked window — large enough to fill a whole
        /// ciphertext pump buffer, for the reason ``receiveBuffer`` documents.
        private static let probeOctets = 64 * 1_024

        @Test(
            "a receive landing mid-send does not corrupt the record stream",
            .timeLimit(.minutes(1)))
        func aConcurrentReceiveDoesNotCorruptTheSendStream() async throws {
            let identity = try DevTLSIdentity.selfSigned()
            let serverContext = try OpenSSLTLS.serverContext(identity)
            defer { CHTTPBoringSSL_SSL_CTX_free(serverContext) }
            let (serverDescriptor, clientDescriptor) = Self.makeSocketPair()
            let loop = try TLSEventLoop()
            loop.start()
            defer { loop.stop() }
            let connection = try Self.makeConnection(
                serverContext,
                descriptor: serverDescriptor,
                loop: loop
            )

            // A pattern rather than a constant fill: a splice that happens to preserve the length is
            // still detectable, which a run of identical octets would hide.
            let payload = (0 ..< Self.payloadOctets).map { UInt8(($0 &* 31 &+ 7) & 0xFF) }
            let clientContext = try #require(
                CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method()))
            CHTTPBoringSSL_SSL_CTX_set_verify(clientContext, SSL_VERIFY_NONE, nil)
            #expect(CHTTPBoringSSLShims_set_client_alpn(clientContext) == 0)
            // `SSL` access is confined to the single background closure below, so the non-Sendable
            // `OpaquePointer` is safe to hand it — `nonisolated(unsafe)` states that invariant.
            nonisolated(unsafe) let clientSSL = try #require(CHTTPBoringSSL_SSL_new(clientContext))
            CHTTPBoringSSL_SSL_set_fd(clientSSL, clientDescriptor)
            defer {
                CHTTPBoringSSL_SSL_free(clientSSL)
                CHTTPBoringSSL_SSL_CTX_free(clientContext)
                _ = close(clientDescriptor)
            }

            let readBack = AsyncEventProbe<[UInt8]>()
            let want = payload.count
            let probe = (0 ..< Self.probeOctets).map { UInt8(($0 &* 13 &+ 3) & 0xFF) }
            DispatchQueue.global()
                .async {
                    guard CHTTPBoringSSL_SSL_connect(clientSSL) == 1 else {
                        return
                    }
                    // Stay silent long enough for the server's send to fill the socket and park with
                    // ciphertext staged. The wait sequences a SETUP step, not an assertion: the parks
                    // themselves are forced by the shrunk buffers, so a slower host waits longer and
                    // still observes the same interleaving.
                    usleep(300_000)
                    _ = probe.withUnsafeBytes {
                        CHTTPBoringSSL_SSL_write(clientSSL, $0.baseAddress, Int32($0.count))
                    }
                    readBack.record(Self.drain(clientSSL, upTo: want))
                }

            try await connection.performHandshake()
            // The two server-side tasks an HTTP/2 connection always has: one sending, one receiving.
            // The sender is UNSTRUCTURED on purpose: the assertions below must be reachable even when
            // the send cannot finish, which is exactly what a corrupted stream causes — the client
            // gives up reading and the writer is left parked on a socket nobody drains.
            let sender = Task { try? await connection.send(payload) }
            let received = try await connection.receive(maxLength: 64)
            #expect(received == Array(probe[..<64]))

            // The client is the oracle: it reads the whole payload back through its own TLS session,
            // so a spliced record stream shows up as a short (failed) read rather than as wrong bytes.
            let echoes = try await readBack.wait(forAtLeast: 1)
            #expect(echoes.first?.count == payload.count)
            #expect(echoes.first == payload)
            // Cancel rather than join: a writer whose readiness registration was lost — which is the
            // OTHER half of the unserialized pump, since the loop keeps one writability handler per
            // descriptor — never completes, and awaiting it would turn a clean failure into a hang.
            await connection.close()
            sender.cancel()
        }

        @Test(
            "an ordinary send and receive leave both direction exclusions free",
            .timeLimit(.minutes(1)))
        func bothExclusionsAreReleasedAfterAnExchange() async throws {
            let identity = try DevTLSIdentity.selfSigned()
            let serverContext = try OpenSSLTLS.serverContext(identity)
            defer { CHTTPBoringSSL_SSL_CTX_free(serverContext) }
            let (serverDescriptor, clientDescriptor) = Self.makeSocketPair()
            let loop = try TLSEventLoop()
            loop.start()
            defer { loop.stop() }
            let connection = try Self.makeConnection(
                serverContext,
                descriptor: serverDescriptor,
                loop: loop
            )

            let clientContext = try #require(
                CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method()))
            CHTTPBoringSSL_SSL_CTX_set_verify(clientContext, SSL_VERIFY_NONE, nil)
            #expect(CHTTPBoringSSLShims_set_client_alpn(clientContext) == 0)
            // Confined to the background closure below, as in the test above.
            nonisolated(unsafe) let clientSSL = try #require(CHTTPBoringSSL_SSL_new(clientContext))
            CHTTPBoringSSL_SSL_set_fd(clientSSL, clientDescriptor)
            let probe = Array("interleave".utf8)
            let echoed = AsyncEventProbe<[UInt8]>()
            DispatchQueue.global()
                .async {
                    guard CHTTPBoringSSL_SSL_connect(clientSSL) == 1 else {
                        return echoed.record([])
                    }
                    _ = probe.withUnsafeBytes {
                        CHTTPBoringSSL_SSL_write(clientSSL, $0.baseAddress, Int32($0.count))
                    }
                    echoed.record(Self.drain(clientSSL, upTo: probe.count))
                }

            try await connection.performHandshake()
            // The handshake drives both directions and must hand both exclusions back, or the first
            // ordinary send would wait on a holder that no longer exists.
            #expect(!connection.isSendPumpHeld)
            #expect(!connection.isReceivePumpHeld)
            let received = try await connection.receive(maxLength: 64)
            #expect(received == probe)
            try await connection.send(try #require(received))
            #expect(!connection.isSendPumpHeld)
            #expect(!connection.isReceivePumpHeld)
            // Join the client before the `defer` frees its `SSL` out from under it.
            let echoes = try await echoed.wait(forAtLeast: 1)
            #expect(echoes.first == probe)
            await connection.close()
            CHTTPBoringSSL_SSL_free(clientSSL)
            CHTTPBoringSSL_SSL_CTX_free(clientContext)
            _ = close(clientDescriptor)
        }

        @Test(
            "concurrent scratch receives cannot copy bytes decrypted by another caller",
            .timeLimit(.minutes(1)))
        func concurrentScratchReceivesPreserveEveryByteExactlyOnce() async throws {
            let identity = try DevTLSIdentity.selfSigned()
            let serverContext = try OpenSSLTLS.serverContext(identity)
            defer { CHTTPBoringSSL_SSL_CTX_free(serverContext) }
            let (serverDescriptor, clientDescriptor) = Self.makeSocketPair()
            let loop = try TLSEventLoop()
            loop.start()
            defer { loop.stop() }
            let connection = try Self.makeConnection(
                serverContext,
                descriptor: serverDescriptor,
                loop: loop
            )

            let clientContext = try #require(
                CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method()))
            CHTTPBoringSSL_SSL_CTX_set_verify(clientContext, SSL_VERIFY_NONE, nil)
            #expect(CHTTPBoringSSLShims_set_client_alpn(clientContext) == 0)
            nonisolated(unsafe) let clientSSL = try #require(CHTTPBoringSSL_SSL_new(clientContext))
            CHTTPBoringSSL_SSL_set_fd(clientSSL, clientDescriptor)
            defer {
                CHTTPBoringSSL_SSL_free(clientSSL)
                CHTTPBoringSSL_SSL_CTX_free(clientContext)
                _ = close(clientDescriptor)
            }

            // Every byte value occurs equally often. Concurrent reads may complete in any order, so
            // compare multisets; a scratch overwrite appears as one duplicated value and one missing
            // value without relying on task scheduling order.
            let payload = (0 ..< 8_192).map(UInt8.init(truncatingIfNeeded:))
            let written = AsyncEventProbe<Int>()
            DispatchQueue.global(qos: .userInitiated)
                .async {
                    guard CHTTPBoringSSL_SSL_connect(clientSSL) == 1 else {
                        return written.record(-1)
                    }
                    let count = payload.withUnsafeBytes {
                        Int(CHTTPBoringSSL_SSL_write(clientSSL, $0.baseAddress, Int32($0.count)))
                    }
                    written.record(count)
                }

            try await connection.performHandshake()
            let received = try await withThrowingTaskGroup(of: UInt8.self) { group in
                for _ in payload.indices {
                    group.addTask {
                        var byte: [UInt8] = []
                        let count = try await connection.receive(into: &byte, maxLength: 1)
                        return try #require(count == 1 ? byte.first : nil)
                    }
                }
                var bytes: [UInt8] = []
                bytes.reserveCapacity(payload.count)
                for try await byte in group {
                    bytes.append(byte)
                }
                return bytes
            }
            #expect(try await written.wait(forAtLeast: 1).first == payload.count)
            #expect(Self.histogram(received) == Self.histogram(payload))
            await connection.close()
        }

        // MARK: - Harness

        /// A connected `SOCK_STREAM` pair with both directions' socket buffers shrunk, so a send of
        /// more than a few KiB is certain to park on writability rather than complete in one write.
        private static func makeSocketPair() -> (server: Int32, client: Int32) {
            var descriptors = [Int32](repeating: 0, count: 2)
            let paired = descriptors.withUnsafeMutableBufferPointer { buffer in
                #if canImport(Darwin)
                    socketpair(AF_UNIX, SOCK_STREAM, 0, buffer.baseAddress)
                #else
                    socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, buffer.baseAddress)
                #endif
            }
            #expect(paired == 0)
            let width = socklen_t(MemoryLayout<Int32>.size)
            var small = Self.sendBuffer
            var large = Self.receiveBuffer
            _ = setsockopt(descriptors[0], SOL_SOCKET, SO_SNDBUF, &small, width)
            _ = setsockopt(descriptors[1], SOL_SOCKET, SO_RCVBUF, &small, width)
            _ = setsockopt(descriptors[0], SOL_SOCKET, SO_RCVBUF, &large, width)
            _ = setsockopt(descriptors[1], SOL_SOCKET, SO_SNDBUF, &large, width)
            // A per-read watchdog on the CLIENT, so a stream that stops arriving surfaces as a short
            // read the assertions can name rather than as a hung process. Five seconds against reads
            // that complete in microseconds — a bound, not a measurement.
            var patience = timeval(tv_sec: 5, tv_usec: 0)
            _ = setsockopt(
                descriptors[1],
                SOL_SOCKET,
                SO_RCVTIMEO,
                &patience,
                socklen_t(MemoryLayout<timeval>.size)
            )
            POSIXSocket.setNonBlocking(descriptors[0])
            return (descriptors[0], descriptors[1])
        }

        /// The server side: a `PortableTLSConnection` over memory BIOs on the readiness loop.
        private static func makeConnection(
            _ context: OpaquePointer,
            descriptor: Int32,
            loop: TLSEventLoop
        ) throws -> PortableTLSConnection {
            let ssl = try #require(CHTTPBoringSSL_SSL_new(context))
            let readBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            let writeBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            CHTTPBoringSSL_SSL_set_bio(ssl, readBIO, writeBIO)
            return PortableTLSConnection(
                id: TransportConnectionID(1),
                peer: TransportAddress(host: "127.0.0.1", port: 0),
                ssl: ssl,
                readBIO: readBIO,
                writeBIO: writeBIO,
                descriptor: descriptor,
                eventLoop: loop,
                clientAuth: .none,
                verifyPeer: nil
            )
        }

        /// Reads up to `limit` plaintext octets from a blocking client `SSL`, stopping early on any
        /// non-positive result — which is how a corrupted record stream surfaces here.
        private static func drain(_ ssl: OpaquePointer, upTo limit: Int) -> [UInt8] {
            var collected: [UInt8] = []
            collected.reserveCapacity(limit)
            var window = [UInt8](repeating: 0, count: 32 * 1_024)
            while collected.count < limit {
                let count = window.withUnsafeMutableBytes {
                    Int(CHTTPBoringSSL_SSL_read(ssl, $0.baseAddress, Int32($0.count)))
                }
                guard count > 0 else {
                    break
                }
                collected.append(contentsOf: window[..<count])
            }
            return collected
        }

        private static func histogram(_ bytes: [UInt8]) -> [Int] {
            var counts = [Int](repeating: 0, count: 256)
            for byte in bytes {
                counts[Int(byte)] += 1
            }
            return counts
        }
    }

#endif
