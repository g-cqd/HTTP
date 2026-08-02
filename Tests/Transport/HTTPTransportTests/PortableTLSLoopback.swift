//
//  PortableTLSLoopback.swift
//  HTTPTransportTests
//
//  The loopback every PortableTLS receive/serialization suite drives: a server
//  ``PortableTLSConnection`` over memory BIOs on the readiness loop, and a raw libssl client on the
//  other end of a `socketpair(2)`. Extracted so the suites that assert on concurrency share ONE
//  harness — two copies of a socket-pair setup drift, and a suite asserting a race against a subtly
//  different peer is a suite asserting nothing.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — the opt-in portable build (`HTTP_PORTABLE_TLS`).
//
//  Standards: TLS 1.3 (RFC 8446) + ALPN (RFC 7301) over a POSIX.1-2017 (IEEE Std 1003.1-2017)
//  `socketpair(2)`.
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    import Testing

    @testable import HTTPTransport

    /// The shared PortableTLS loopback harness.
    enum PortableTLSLoopback {
        /// A send window small enough that a multi-record send is certain to park on writability
        /// part-way through a staged chunk, and large enough that the handshake still fits.
        static let narrowSendBuffer: Int32 = 2_048

        /// A receive window deliberately much larger than ``narrowSendBuffer``.
        ///
        /// The asymmetry is what makes an egress/ingress overwrite *observable* rather than merely
        /// present: the ingress pump must be able to read more octets in one `read(2)` than the egress
        /// pump has already put on the wire, or the overwrite lands entirely on octets that have
        /// already left and nothing detectable reaches the peer.
        static let wideReceiveBuffer: Int32 = 256 * 1_024

        /// A connected `SOCK_STREAM` pair with each direction's socket buffers set as given.
        ///
        /// The server side is left non-blocking, which is what the memory-BIO pump requires.
        static func makeSocketPair(
            sendBuffer: Int32 = narrowSendBuffer,
            receiveBuffer: Int32 = wideReceiveBuffer
        ) -> (server: Int32, client: Int32) {
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
            var small = sendBuffer
            var large = receiveBuffer
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

        /// The server side: a ``PortableTLSConnection`` over memory BIOs on the readiness loop.
        static func makeConnection(
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

        /// The client side: a verification-free libssl session bound directly to `descriptor`.
        ///
        /// The caller frees both handles — and must not do so before whatever background closure it
        /// hands the `SSL` to has finished with it.
        static func makeClient(
            descriptor: Int32
        ) throws -> (ssl: OpaquePointer, context: OpaquePointer) {
            let method = CHTTPBoringSSL_TLS_client_method()
            let context = try #require(CHTTPBoringSSL_SSL_CTX_new(method))
            CHTTPBoringSSL_SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
            #expect(CHTTPBoringSSLShims_set_client_alpn(context) == 0)
            let ssl = try #require(CHTTPBoringSSL_SSL_new(context))
            CHTTPBoringSSL_SSL_set_fd(ssl, descriptor)
            return (ssl, context)
        }

        /// Reads up to `limit` plaintext octets from a blocking client `SSL`, stopping early on any
        /// non-positive result — which is how a corrupted record stream surfaces to a peer.
        static func drain(_ ssl: OpaquePointer, upTo limit: Int) -> [UInt8] {
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

        /// Occurrences of each octet value — the order-independent oracle.
        ///
        /// Concurrent receives may complete in any order, so a *sequence* comparison cannot tell a
        /// legal reordering from an illegal loss. A multiset can: an overwrite shows up as one value
        /// counted twice and another not at all.
        static func histogram(_ bytes: some Sequence<UInt8>) -> [Int] {
            var counts = [Int](repeating: 0, count: 256)
            for byte in bytes {
                counts[Int(byte)] += 1
            }
            return counts
        }

        /// A payload in which every octet value occurs exactly `repeats` times.
        static func balancedPayload(repeats: Int) -> [UInt8] {
            (0 ..< (repeats * 256)).map(UInt8.init(truncatingIfNeeded:))
        }
    }

#endif
