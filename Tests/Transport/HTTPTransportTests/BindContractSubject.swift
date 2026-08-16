//
//  BindContractSubject.swift
//  HTTPTransportTests
//
//  One listener under test, reduced to the four things the bind contract needs: bind, report what was
//  bound, be reachable there, and stop. A single value type with closures rather than a protocol and
//  two wrapper classes, so the TCP (`ServerTransport`) and QUIC (`QUICServerTransport`) sides — which
//  are deliberately different protocols — become one column type in the matrix.
//
//  `dial` is the part that matters most: audit F-04 was a listener that bound one port and REPORTED
//  another, so reading `boundPort` back is not evidence. Every non-failing row dials the endpoint the
//  listener claims and requires a real client to arrive there — a raw `connect(2)` + echo for TCP, a
//  real QUIC handshake (RFC 9000) for QUIC.
//

import Foundation
import Synchronization
import Testing

@testable import HTTPTransport

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif
#if canImport(Network)
    internal import Network
#endif

/// A bound listener under the bind contract, whatever protocol or backbone implements it.
struct BindContractSubject: Sendable {
    /// The port the listener reports, `0` before binding.
    let boundPort: @Sendable () -> UInt16
    /// The endpoint the listener reports, `nil` where the backbone does not implement it yet.
    let boundEndpoint: @Sendable () -> BindEndpoint?
    /// Connects a real client to `endpoint` and returns whether it arrived.
    let dial: @Sendable (BindEndpoint) async -> Bool
    /// Stops the listener and releases the port.
    let stop: @Sendable () async -> Void

    /// Binds `backbone` for `configuration` and returns the running subject, or throws its bind error.
    static func start(
        _ backbone: BindContractBackbone,
        host: String,
        port: UInt16
    ) async throws -> Self {
        guard backbone.isQUIC else {
            return try await startTCP(backbone, host: host, port: port)
        }
        return try await startQUIC(backbone, host: host, port: port)
    }

    // MARK: - TCP

    private static func startTCP(
        _ backbone: BindContractBackbone,
        host: String,
        port: UInt16
    ) async throws -> Self {
        guard let selected = backbone.transportBackbone else {
            throw TransportError.unsupported("\(backbone.rawValue) is not a TCP backbone")
        }
        // The portableTLS column listens with a TLS identity and is dialed with a real handshake —
        // its plaintext is inside the TLS session, so a cleartext `connect(2)` + echo would prove
        // reachability of the port but not that the listener behind it serves. Same dial-don't-trust
        // rule as every other column, one protocol layer up.
        let secured = selected == .portableTLS
        let transport = try TransportFactory.make(
            TransportConfiguration(
                host: host,
                port: port,
                backbone: selected,
                tls: secured ? try Self.portableTLSIdentity() : nil
            )
        )
        let stream = try await transport.start()
        // The stream is captured by every closure below, so it outlives the call: releasing it
        // terminates the `AsyncStream`, whose `onTermination` shuts the transport down — which would
        // dissolve the very bind the matrix is about.
        let echo = Task { await serveOneEcho(stream) }
        return Self(
            boundPort: { transport.boundPort },
            boundEndpoint: { transport.boundEndpoint },
            dial: { endpoint in
                secured
                    ? await portableTLSRoundTrip(to: endpoint)
                    : await tcpRoundTrip(to: endpoint)
            },
            stop: {
                echo.cancel()
                await transport.shutdown()
                withExtendedLifetime(stream) {
                    // Held until the listener is down.
                }
            }
        )
    }

    /// Accepts one connection and echoes its first chunk, so a dial has something to round-trip with.
    private static func serveOneEcho(_ stream: AsyncStream<any TransportConnection>) async {
        for await connection in stream {
            if let chunk = try? await connection.receive(maxLength: 64) {
                try? await connection.send(chunk)
            }
            await connection.close()
        }
    }

    /// `connect(2)` to `endpoint` in its own family, send four bytes, require them back.
    ///
    /// The descriptor carries `SO_RCVTIMEO`/`SO_SNDTIMEO`. Without them a server that never echoes
    /// parks `recv(2)` forever on a Swift cooperative-pool thread, and with a matrix this wide that
    /// starves the pool: the observed symptom was a dozen unrelated tests hitting their 60 s limit at
    /// once. A bounded blocking read fails the cell instead of the suite.
    private static func tcpRoundTrip(to endpoint: BindEndpoint) async -> Bool {
        let descriptor = connect(to: endpoint)
        guard descriptor >= 0 else {
            return false
        }
        defer { close(descriptor) }
        setDeadline(descriptor)
        let payload = Array("ping".utf8)
        let sent = payload.withUnsafeBytes { raw in
            #if canImport(Darwin)
                Darwin.send(descriptor, raw.baseAddress, raw.count, 0)
            #else
                // `MSG_NOSIGNAL`, because Linux has no `SO_NOSIGPIPE`: a peer RST mid-write must be
                // `EPIPE`, not a fatal signal that takes the test process down (audit T-F1).
                Glibc.send(descriptor, raw.baseAddress, raw.count, Int32(MSG_NOSIGNAL))
            #endif
        }
        guard sent == payload.count else {
            return false
        }
        var echo = [UInt8](repeating: 0, count: 64)
        let read = echo.withUnsafeMutableBytes { raw in
            #if canImport(Darwin)
                Darwin.recv(descriptor, raw.baseAddress, raw.count, 0)
            #else
                Glibc.recv(descriptor, raw.baseAddress, raw.count, 0)
            #endif
        }
        guard read == payload.count else {
            return false
        }
        return Array(echo.prefix(payload.count)) == payload
    }

    // MARK: - QUIC

    #if canImport(Network)
        /// The dev identity, generated ONCE per process.
        ///
        /// `DevTLSIdentity.selfSigned` shells out to `openssl` for an RSA-2048 key and a certificate.
        /// The matrix asks for a QUIC listener twenty-two times, and paying that per cell starved the
        /// suite's real-network permit pool until unrelated tests timed out. The identity is not what
        /// any row is about, so it is a fixture, not a per-cell cost.
        private static let cachedIdentity = Mutex<TransportTLS?>(nil)

        /// The shared dev identity for every QUIC column.
        private static func devIdentity() throws -> TransportTLS {
            if let cached = cachedIdentity.withLock(\.self) {
                return cached
            }
            let fresh = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
            cachedIdentity.withLock { $0 = fresh }
            return fresh
        }

        private static func startQUIC(
            _ backbone: BindContractBackbone,
            host: String,
            port: UInt16
        ) async throws -> Self {
            let tls = try devIdentity()
            let configuration = TransportConfiguration(
                host: host,
                port: port,
                backbone: .networkFramework,
                tls: tls
            )
            let transport: any QUICServerTransport
            if backbone == .quicModern {
                guard #available(macOS 26, iOS 26, *) else {
                    throw TransportError.unsupported("ModernQUICTransport needs macOS 26 / iOS 26")
                }
                transport = ModernQUICTransport(configuration: configuration)
            }
            else {
                transport = LegacyQUICTransport(configuration: configuration)
            }
            let stream = try await transport.start()
            let drain = Task { await drainQUIC(stream) }
            return Self(
                boundPort: { transport.boundPort },
                boundEndpoint: { transport.boundEndpoint },
                dial: { endpoint in await quicHandshake(to: endpoint) },
                stop: {
                    drain.cancel()
                    await transport.shutdown()
                    withExtendedLifetime(stream) {
                        // Held until the listener is down.
                    }
                }
            )
        }

        /// Keeps the QUIC connection stream consumed so its continuation is never terminated early.
        private static func drainQUIC(_ stream: AsyncStream<any QUICConnection>) async {
            for await connection in stream {
                _ = connection
            }
        }

        /// Completes a real QUIC handshake (RFC 9000) against `endpoint` with ALPN `h3` (RFC 7301).
        ///
        /// Reaching `.ready` is the assertion: the UDP port the listener REPORTED is the one a QUIC
        /// client actually lands on. Peer verification is disabled because the listener carries the
        /// self-signed dev identity; this proves reachability, not trust.
        private static func quicHandshake(to endpoint: BindEndpoint) async -> Bool {
            let options = NWProtocolQUIC.Options(alpn: ["h3"])
            sec_protocol_options_set_verify_block(
                options.securityProtocolOptions,
                { _, _, complete in complete(true) },
                DispatchQueue(label: "bind.contract.quic.verify")
            )
            let host: NWEndpoint.Host
            switch endpoint.family {
                case .ipv4:
                    guard let address = IPv4Address(endpoint.address) else {
                        return false
                    }
                    host = .ipv4(address)
                case .ipv6:
                    guard let address = IPv6Address(endpoint.address) else {
                        return false
                    }
                    host = .ipv6(address)
            }
            let client = NWConnection(
                host: host,
                port: NWEndpoint.Port(rawValue: endpoint.port) ?? .any,
                using: NWParameters(quic: options)
            )
            defer { client.cancel() }
            return await withCheckedContinuation {
                (continuation: CheckedContinuation<Bool, Never>) in
                let settled = ModernOnceLatch()
                client.stateUpdateHandler = { state in
                    switch state {
                        case .ready where settled.take():
                            continuation.resume(returning: true)
                        case .failed where settled.take():
                            continuation.resume(returning: false)
                        case .cancelled where settled.take():
                            continuation.resume(returning: false)
                        default:
                            break
                    }
                }
                client.start(queue: DispatchQueue(label: "bind.contract.quic.client"))
            }
        }
    #else
        /// Linux has no Network.framework, so the QUIC columns are compiled out of the package there.
        ///
        /// Reached only if the matrix ever stops skipping them on this platform, which
        /// `BindContractCoverageTests` asserts it does not.
        private static func startQUIC(
            _ backbone: BindContractBackbone,
            host _: String,
            port _: UInt16
        ) async throws -> Self {
            throw TransportError.unsupported("\(backbone.rawValue) is Network.framework-only")
        }
    #endif

    // MARK: - Raw client sockets

    /// Opens a blocking client connection to a numeric endpoint (no name resolution in the path).
    ///
    /// Internal rather than private: the portableTLS column's dial
    /// (`BindContractSubject+PortableTLS.swift`) reuses it, so both dials reach a listener the same
    /// way and differ only in what they speak once connected.
    static func connect(to endpoint: BindEndpoint) -> Int32 {
        switch endpoint.family {
            case .ipv4:
                var target = sockaddr_in()
                #if canImport(Darwin)
                    target.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                #endif
                target.sin_family = sa_family_t(AF_INET)
                target.sin_port = endpoint.port.bigEndian
                guard inet_pton(AF_INET, endpoint.address, &target.sin_addr) == 1 else {
                    return -1
                }
                return dial(AF_INET, &target, socklen_t(MemoryLayout<sockaddr_in>.size))
            case .ipv6:
                var target = sockaddr_in6()
                #if canImport(Darwin)
                    target.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                #endif
                target.sin6_family = sa_family_t(AF_INET6)
                target.sin6_port = endpoint.port.bigEndian
                guard inet_pton(AF_INET6, endpoint.address, &target.sin6_addr) == 1 else {
                    return -1
                }
                return dial(AF_INET6, &target, socklen_t(MemoryLayout<sockaddr_in6>.size))
        }
    }

    /// Bounds every blocking read and write on `descriptor` (POSIX.1-2017 `SO_RCVTIMEO`/`SO_SNDTIMEO`).
    ///
    /// Internal for the same reason as ``connect(to:)`` — the TLS dial's handshake and reads carry
    /// the same bound as the cleartext dial's.
    static func setDeadline(_ descriptor: Int32, seconds: Int = 5) {
        var deadline = timeval(tv_sec: seconds, tv_usec: 0)
        let size = socklen_t(MemoryLayout<timeval>.size)
        _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &deadline, size)
        _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &deadline, size)
    }

    /// `socket` + `connect` for an already-populated `sockaddr_in`/`sockaddr_in6`.
    private static func dial<Address>(
        _ domain: Int32, _ target: inout Address, _ length: socklen_t
    ) -> Int32 {
        let descriptor = socket(domain, streamSocketType, 0)
        guard descriptor >= 0 else {
            return -1
        }
        let connected = withUnsafePointer(to: &target) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                #if canImport(Darwin)
                    Darwin.connect(descriptor, address, length) == 0
                #else
                    Glibc.connect(descriptor, address, length) == 0
                #endif
            }
        }
        guard connected else {
            close(descriptor)
            return -1
        }
        return descriptor
    }

    /// `SOCK_STREAM` as an `Int32` — it imports as a plain `Int32` on Darwin but as the
    /// `__socket_type` enum on Glibc, the same divergence `POSIXSocket` normalizes.
    static var streamSocketType: Int32 {
        #if canImport(Darwin)
            SOCK_STREAM
        #else
            Int32(SOCK_STREAM.rawValue)
        #endif
    }

    /// `SOCK_DGRAM` as an `Int32`, for probing a free UDP port for the QUIC columns.
    static var datagramSocketType: Int32 {
        #if canImport(Darwin)
            SOCK_DGRAM
        #else
            Int32(SOCK_DGRAM.rawValue)
        #endif
    }

    /// Lets the kernel pick a free loopback port of `family`, then releases it for the listener.
    static func unusedPort(_ type: Int32) throws -> UInt16 {
        let descriptor = socket(AF_INET, type, 0)
        guard descriptor >= 0 else {
            throw TransportError.bindFailed("socket() errno \(errno)")
        }
        defer { close(descriptor) }
        var address = sockaddr_in()
        #if canImport(Darwin)
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        guard bound else {
            throw TransportError.bindFailed("bind() errno \(errno)")
        }
        var assigned = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let read = withUnsafeMutablePointer(to: &assigned) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length) == 0
            }
        }
        guard read else {
            throw TransportError.bindFailed("getsockname() errno \(errno)")
        }
        return UInt16(bigEndian: assigned.sin_port)
    }
}
