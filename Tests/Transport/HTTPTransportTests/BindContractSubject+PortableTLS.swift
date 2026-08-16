//
//  BindContractSubject+PortableTLS.swift
//  HTTPTransportTests
//
//  The portableTLS column's half of ``BindContractSubject``: the shared dev identity its listener
//  carries, and the dial that proves a cell — a real TLS 1.3 handshake plus a plaintext echo through
//  the session, using the same loopback client harness (``PortableTLSLoopback``) every PortableTLS
//  suite drives, over the same raw `connect(2)` the cleartext columns dial with.
//
//  Split from `BindContractSubject.swift` because only this part is trait-gated: with
//  `HTTP_PORTABLE_TLS` off the libssl client does not exist, so the `#else` half supplies stubs that
//  keep the column *named* in the grid while `BindContractCoverageTests` pins that it skips, by
//  reason, rather than runs. The stubs are unreachable in that configuration — reaching one means the
//  skip pin has already failed.
//
//  Standards: TLS 1.3 (RFC 8446) + ALPN (RFC 7301) over TCP (RFC 9293), POSIX.1-2017 sockets;
//  IPv4 RFC 791 / IPv6 RFC 4291 literals.
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    import Synchronization

    @testable import HTTPTransport

    extension BindContractSubject {
        /// The dev identity for the portableTLS column, generated ONCE per process.
        ///
        /// Same economics as the QUIC columns' `cachedIdentity`: `DevTLSIdentity.selfSigned` shells
        /// out to `openssl` for an RSA-2048 key, the matrix asks for this listener eleven times, and
        /// the identity is not what any row is about.
        private static let cachedPortableIdentity = Mutex<TransportTLS?>(nil)

        /// The shared dev identity carried by every portableTLS cell's listener.
        static func portableTLSIdentity() throws -> TransportTLS {
            if let cached = cachedPortableIdentity.withLock(\.self) {
                return cached
            }
            let fresh = try DevTLSIdentity.selfSigned()
            cachedPortableIdentity.withLock { $0 = fresh }
            return fresh
        }

        /// Dials `endpoint` with a full TLS handshake, sends four plaintext bytes, requires them back.
        ///
        /// The TLS twin of ``tcpRoundTrip(to:)``, and the same argument: reading `boundPort` back is
        /// never the assertion, so the cell is proven by a real client arriving — here that means the
        /// handshake settling (which is also what makes the transport surface the connection at all)
        /// and the echo crossing the session. Blocking, but bounded by ``setDeadline(_:seconds:)`` on
        /// the descriptor, so a listener that never answers fails the cell instead of the suite.
        static func portableTLSRoundTrip(to endpoint: BindEndpoint) async -> Bool {
            let descriptor = connect(to: endpoint)
            guard descriptor >= 0 else {
                return false
            }
            defer { _ = close(descriptor) }
            setDeadline(descriptor)
            guard let client = try? PortableTLSLoopback.makeClient(descriptor: descriptor) else {
                return false
            }
            defer {
                CHTTPBoringSSL_SSL_free(client.ssl)
                CHTTPBoringSSL_SSL_CTX_free(client.context)
            }
            guard CHTTPBoringSSL_SSL_connect(client.ssl) == 1 else {
                return false
            }
            let payload = [UInt8]("ping".utf8)
            let wrote = payload.withUnsafeBytes { raw in
                CHTTPBoringSSL_SSL_write(client.ssl, raw.baseAddress, Int32(raw.count))
            }
            guard wrote == Int32(payload.count) else {
                return false
            }
            let echoed = PortableTLSLoopback.drain(client.ssl, upTo: payload.count)
            return echoed == payload
        }
    }

#else

    @testable import HTTPTransport

    extension BindContractSubject {
        /// Unreachable without `HTTP_PORTABLE_TLS`: the coverage pin asserts the column skips.
        static func portableTLSIdentity() throws -> TransportTLS {
            throw TransportError.unsupported(
                "the portableTLS column requires building with HTTP_PORTABLE_TLS=1"
            )
        }

        /// Unreachable without `HTTP_PORTABLE_TLS`, for the same reason as the identity stub.
        static func portableTLSRoundTrip(to _: BindEndpoint) async -> Bool {
            false
        }
    }

#endif
