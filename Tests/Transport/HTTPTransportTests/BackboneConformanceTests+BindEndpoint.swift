//
//  BackboneConformanceTests+BindEndpoint.swift
//  HTTPTransportTests
//
//  The bind-endpoint half of the one shared backbone battery: what ``TransportConfiguration``'s `host`
//  and `port` MEAN, asserted identically on every socket backbone. Declared as an extension of
//  ``BackboneConformanceTests`` rather than a second suite so there is literally one suite — the drift
//  between backbones is the defect class (audit F-04: QUIC ignored the port; F-05: Network.framework
//  ignored the host), and a second suite is how two backbones start diverging again.
//
//  The table these tests encode, per ``BindEndpoint``:
//
//    host              → binds                                    → a failed bind is
//    "127.0.0.1"         the IPv4 loopback interface only            n/a
//    "::1"               the IPv6 loopback interface only            n/a
//    "0.0.0.0"           every IPv4 interface (RFC 1122 §3.2.1.3)    n/a
//    "::"                every IPv6 interface (RFC 4291 §2.5.2)      n/a
//    "localhost"         the first AI_PASSIVE answer, resolved once  n/a
//    a local interface   that interface only                         n/a
//    "192.0.2.1"         nothing — RFC 5737, no host owns it         TransportError.bindFailed
//    "…​.invalid"         nothing — RFC 2606 §2 reserved TLD          TransportError.bindFailed
//
//    port 0            → an OS-chosen ephemeral port, reported by `boundPort`
//    port N            → exactly N; another listener holding N is TransportError.bindFailed
//
//  Standards: getaddrinfo(3) AI_PASSIVE (POSIX.1-2017); IPv4 RFC 791 / IPv6 RFC 4291 literals;
//  RFC 5737 §3 (IPv4 documentation range, unassignable); RFC 2606 §2 (`.invalid` never resolves);
//  TCP RFC 9293.
//

internal import Darwin
import HTTPTestSupport
import Testing

@testable import HTTPTransport

extension BackboneConformanceTests {
    /// Every host spelling a listener must accept, with the loopback literal a client reaches it on.
    ///
    /// The client target is derived from ``BindEndpoint`` rather than hard-coded, so the test also
    /// asserts that the resolver and the backbone agree about which family a spelling selects.
    static let bindableHosts = ["127.0.0.1", "::1", "0.0.0.0", "::", "localhost"]

    /// Every host spelling that must fail closed rather than land on some other interface.
    ///
    /// `192.0.2.1` is RFC 5737 TEST-NET-1 — reserved for documentation, so no host is assigned it.
    /// `bind-target.invalid` is RFC 2606 §2's reserved TLD, which resolves nowhere. A backbone that
    /// starts on either has silently widened the listener's exposure (CWE-668).
    static let unbindableHosts = ["192.0.2.1", "bind-target.invalid"]

    @Test(
        "every host spelling binds its own family and accepts there",
        .timeLimit(.minutes(1)), arguments: socketBackbones, bindableHosts)
    func hostSpellingBindsAndAccepts(
        _ backbone: TransportBackbone, _ host: String
    ) async throws {
        let resolved = try BindEndpoint.resolve(host: host, port: 0)
        let transport = try TransportFactory.make(
            TransportConfiguration(host: host, port: 0, backbone: backbone)
        )
        let stream = try await transport.start()
        #expect(transport.boundPort != 0, "\(backbone.rawValue) bound no port for host \(host)")

        // A wildcard is reachable through the loopback of its own family; an interface pin is reachable
        // at the literal it pinned.
        let target =
            resolved.isWildcard ? Self.loopbackLiteral(of: resolved.family) : resolved.address
        await Self.assertEcho(
            stream: stream,
            address: target,
            family: resolved.family,
            port: transport.boundPort
        )
        await transport.shutdown()
    }

    @Test(
        "an unbindable configured host fails closed on every backbone",
        .timeLimit(.minutes(1)), arguments: socketBackbones, unbindableHosts)
    func unbindableHostFailsClosed(
        _ backbone: TransportBackbone, _ host: String
    ) async throws {
        let transport = try TransportFactory.make(
            TransportConfiguration(host: host, port: 0, backbone: backbone)
        )
        await #expect(throws: TransportError.self) {
            _ = try await transport.start()
            await transport.shutdown()
        }
    }

    @Test(
        "a configured non-zero port is the port that binds",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func configuredPortIsHonored(_ backbone: TransportBackbone) async throws {
        let requested = try Self.unusedTCPPort()
        let transport = try TransportFactory.make(
            TransportConfiguration(host: "127.0.0.1", port: requested, backbone: backbone)
        )
        // The stream must stay alive for the whole test: dropping it terminates the `AsyncStream`,
        // whose `onTermination` shuts the transport down underneath the assertions.
        let stream = try await transport.start()
        #expect(
            transport.boundPort == requested,
            "\(backbone.rawValue) was configured for \(requested) but bound \(transport.boundPort)"
        )
        withExtendedLifetime(stream) {
            // Held until the assertions above are done.
        }
        await transport.shutdown()
    }

    @Test(
        "port 0 stays an explicit ephemeral request, realized and reported",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func ephemeralPortIsRealized(_ backbone: TransportBackbone) async throws {
        let transport = try makeTransport(backbone)
        let stream = try await transport.start()
        let port = transport.boundPort
        #expect(port != 0, "\(backbone.rawValue) did not realize an ephemeral port")
        // Reported *and* real: the F-04 failure mode was a listener that bound one port and announced
        // another, so the announcement has to be dialled, not just read back.
        await Self.assertEcho(stream: stream, address: "127.0.0.1", family: .ipv4, port: port)
        await transport.shutdown()
    }

    @Test(
        "a second listener on the same port fails closed instead of silently sharing it",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func portConflictFailsClosed(_ backbone: TransportBackbone) async throws {
        let holder = try makeTransport(backbone)
        // Held for the whole test — see `configuredPortIsHonored`: releasing the stream releases the
        // port, and the conflict this test is about would evaporate.
        let held = try await holder.start()
        let port = holder.boundPort
        #expect(port != 0)

        let clashing = try TransportFactory.make(
            TransportConfiguration(host: "127.0.0.1", port: port, backbone: backbone)
        )
        await #expect(throws: TransportError.self) {
            let clashingStream = try await clashing.start()
            withExtendedLifetime(clashingStream) {
                // Held so a successful bind is observable rather than instantly undone.
            }
            await clashing.shutdown()
        }
        withExtendedLifetime(held) {
            // The holder must keep the port for the whole clash attempt.
        }
        await holder.shutdown()
    }

    /// Backbones whose `shutdown()` hands the listening descriptor to its event loop to close and
    /// returns without waiting, so the port is still bound when the call returns.
    ///
    /// `POSIXKqueueTransport.shutdown()` and `SwiftSystemTransport.shutdown()` both end in
    /// `acceptLoop.closeDescriptor(listenFD)`, which enqueues the close onto the loop thread. A restart
    /// on the same configured port therefore races that close and loses with `EADDRINUSE`. That is the
    /// same "the contract is not actually honored" defect this battery exists for, one layer down —
    /// but `POSIXKqueue/` and `SwiftSystem/` are owned elsewhere, so it is recorded as a known issue
    /// rather than silently dropped from the arguments: if either backbone starts awaiting its close,
    /// this trait fails as "known issue not recorded" and the exclusion has to be removed.
    static let asynchronousListenerClose: Set<TransportBackbone> = [.posixKqueue, .swiftSystem]

    @Test(
        "stop then restart rebinds the same configured port, repeatedly",
        .timeLimit(.minutes(1)), arguments: socketBackbones)
    func stopRestartRebindsTheSamePort(_ backbone: TransportBackbone) async throws {
        let requested = try Self.unusedTCPPort()
        // Four rapid cycles: each `shutdown` must actually release the port before the next `start`,
        // which is the property a graceful restart (and a TLS reload) depends on.
        guard Self.asynchronousListenerClose.contains(backbone) else {
            try await Self.rebindCycles(backbone, port: requested)
            return
        }
        await withKnownIssue(
            "\(backbone.rawValue) closes its listening descriptor asynchronously at shutdown",
            isIntermittent: true
        ) {
            try await Self.rebindCycles(backbone, port: requested)
        }
    }

    /// Starts, round-trips and stops a listener on `port` four times in a row.
    private static func rebindCycles(_ backbone: TransportBackbone, port: UInt16) async throws {
        for cycle in 0 ..< 4 {
            let transport = try TransportFactory.make(
                TransportConfiguration(host: "127.0.0.1", port: port, backbone: backbone)
            )
            let stream = try await transport.start()
            #expect(
                transport.boundPort == port,
                "\(backbone.rawValue) cycle \(cycle) bound \(transport.boundPort), not \(port)"
            )
            await assertEcho(stream: stream, address: "127.0.0.1", family: .ipv4, port: port)
            await transport.shutdown()
        }
    }

    // MARK: - Helpers

    /// The loopback literal of `family` — where a wildcard-bound listener is reachable.
    static func loopbackLiteral(of family: BindEndpoint.Family) -> String {
        switch family {
            case .ipv4:
                "127.0.0.1"
            case .ipv6:
                "::1"
        }
    }

    /// Round-trips one payload against a started transport through a raw client socket of `family`.
    ///
    /// A raw descriptor rather than an `NWConnection`: the point is to dial the *numeric* literal the
    /// listener claims to have bound, in the family it claims, with no name resolution in between.
    static func assertEcho(
        stream: AsyncStream<any TransportConnection>,
        address: String,
        family: BindEndpoint.Family,
        port: UInt16
    ) async {
        let server = Task {
            var iterator = stream.makeAsyncIterator()
            guard let connection = await iterator.next() else {
                return
            }
            if let chunk = try? await connection.receive(maxLength: 64) {
                try? await connection.send(chunk)
            }
            await connection.close()
        }
        defer { server.cancel() }

        let descriptor = connect(to: address, family: family, port: port)
        #expect(descriptor >= 0, "could not dial \(address):\(port)")
        guard descriptor >= 0 else {
            return
        }
        defer { close(descriptor) }

        let payload = Array("ping".utf8)
        let sent = payload.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, $0.count, 0) }
        #expect(sent == payload.count)
        var echo = [UInt8](repeating: 0, count: 64)
        let read = echo.withUnsafeMutableBytes {
            Darwin.recv(descriptor, $0.baseAddress, $0.count, 0)
        }
        #expect(read == payload.count)
        #expect(read > 0 ? Array(echo.prefix(max(read, 0))) == payload : false)
        _ = await server.result
    }

    /// Opens a blocking client connection to a numeric `address` of `family` (no name resolution).
    static func connect(to address: String, family: BindEndpoint.Family, port: UInt16) -> Int32 {
        switch family {
            case .ipv4:
                var target = sockaddr_in()
                target.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                target.sin_family = sa_family_t(AF_INET)
                target.sin_port = port.bigEndian
                guard inet_pton(AF_INET, address, &target.sin_addr) == 1 else {
                    return -1
                }
                return dial(AF_INET, &target, socklen_t(MemoryLayout<sockaddr_in>.size))
            case .ipv6:
                var target = sockaddr_in6()
                target.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                target.sin6_family = sa_family_t(AF_INET6)
                target.sin6_port = port.bigEndian
                guard inet_pton(AF_INET6, address, &target.sin6_addr) == 1 else {
                    return -1
                }
                return dial(AF_INET6, &target, socklen_t(MemoryLayout<sockaddr_in6>.size))
        }
    }

    /// `socket` + `connect` for an already-populated `sockaddr_in`/`sockaddr_in6`.
    private static func dial<Address>(
        _ domain: Int32, _ target: inout Address, _ length: socklen_t
    ) -> Int32 {
        let descriptor = socket(domain, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            return -1
        }
        let connected = withUnsafePointer(to: &target) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, length) == 0
            }
        }
        guard connected else {
            close(descriptor)
            return -1
        }
        return descriptor
    }

    /// Lets the kernel pick a free loopback TCP port, then releases it for the listener under test.
    static func unusedTCPPort() throws -> UInt16 {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw TransportError.bindFailed("socket() errno \(errno)")
        }
        defer { close(descriptor) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
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
