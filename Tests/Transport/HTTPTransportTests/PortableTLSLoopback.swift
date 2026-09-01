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

        /// A PEM-based dev `TransportTLS` for the server side.
        ///
        /// PEM is the identity currency BOTH portable engines read (Phase 3d: the HTTPTLS
        /// engine does not parse PKCS#12; the legacy engine reads PEM through `use_pem`).
        /// Callers flip `clientAuth`/`verifyPeer`/`sniIdentities` on the returned value —
        /// they are plain vars.
        static func devTLS(commonName: String = "localhost") throws -> TransportTLS {
            let pem = try DevTLSIdentity.selfSignedPEM(commonName: commonName)
            return TransportTLS(
                pem: TransportTLS.PEMIdentity(
                    certificateChainPEM: pem.certificatePEM,
                    privateKeyPEM: pem.privateKeyPEM
                )
            )
        }

        /// A PEM-based dev SNI identity for `commonName` (see ``devTLS(commonName:)``).
        static func devSNIIdentity(
            commonName: String
        ) throws -> TransportTLS.SNIIdentity {
            let pem = try DevTLSIdentity.selfSignedPEM(commonName: commonName)
            return TransportTLS.SNIIdentity(
                pem: TransportTLS.PEMIdentity(
                    certificateChainPEM: pem.certificatePEM,
                    privateKeyPEM: pem.privateKeyPEM
                )
            )
        }

        /// The server context for `tls` — whichever engine flavor this build compiled.
        static func makeServerContext(
            _ tls: TransportTLS
        ) throws -> PortableTLSServerContext {
            try PortableTLSServerContext(tls)
        }

        /// The server side: a ``PortableTLSConnection`` on the readiness loop, its engine
        /// minted by `context` (an `SSL` over memory BIOs on the legacy flavor, a sans-I/O
        /// `TLSServerConnection` on the HTTPTLS one).
        static func makeConnection(
            _ context: PortableTLSServerContext,
            descriptor: Int32,
            loop: TLSEventLoop,
            clientAuth: TransportTLS.ClientAuth = .none,
            verifyPeer: (@Sendable ([[UInt8]]) -> Bool)? = nil
        ) throws -> PortableTLSConnection {
            let id = TransportConnectionID(1)
            // `guard let` rather than `#require`: the engine is `~Copyable`, which the
            // macro's generic parameter cannot carry.
            guard let engine = context.makeEngine(connectionID: id) else {
                throw TransportError.tlsConfigurationFailed("the context minted no engine")
            }
            return PortableTLSConnection(
                id: id,
                peer: TransportAddress(host: "127.0.0.1", port: 0),
                engine: engine,
                descriptor: descriptor,
                eventLoop: loop,
                clientAuth: clientAuth,
                verifyPeer: verifyPeer
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

        /// The peer (server) leaf certificate's Common Name on a handshaken client `SSL`.
        ///
        /// The client oracle's own reading of which certificate the server served (the SNI
        /// suites' oracle). Mirrors the legacy `OpenSSLTLS.peerSubject`, owned here because
        /// the client side stays BoringSSL under both gates.
        static func peerSubject(of ssl: OpaquePointer) -> String? {
            var buffer = [CChar](repeating: 0, count: 256)
            let length = buffer.withUnsafeMutableBufferPointer {
                CHTTPBoringSSLShims_peer_subject(ssl, $0.baseAddress, Int32($0.count))
            }
            guard length >= 0 else {
                return nil
            }
            let bytes = buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) }
            return String(decoding: bytes, as: Unicode.UTF8.self)
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
