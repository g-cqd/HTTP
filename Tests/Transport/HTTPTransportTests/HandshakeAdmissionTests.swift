//
//  HandshakeAdmissionTests.swift
//  HTTPTransportTests
//
//  The half of audit finding 8 that only a TLS backbone can demonstrate: the ceiling must cover
//  connections that are still *handshaking*, not just ones being served. The portable TLS backbone
//  charges its slot before `SSL_new` and before the handshake runs, so a peer that completes the TCP
//  connect and then never sends a ClientHello — the Slowloris-shaped case — is holding a slot even
//  though nothing has been yielded to the server. Charging after the handshake (or, as before, inside
//  the server's serve task) would leave that peer entirely unaccounted for.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — runs only in the opt-in portable build
//  (`HTTP_PORTABLE_TLS`).
//
//  Standards: TLS 1.3 (RFC 8446) over TCP (RFC 9293); a resource-exhaustion defense in the spirit of
//  RFC 9110 §15.5.30 (429) — CWE-770, CWE-400.
//

#if canImport(CHTTPBoringSSLShims)

    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Handshaking connections count against the ceiling (audit F8)", .realNetwork)
    struct HandshakeAdmissionTests {
        @Test(
            "a peer that connects and never sends a ClientHello still holds its slot",
            .timeLimit(.minutes(1))
        )
        func stalledHandshakeHoldsItsSlot() async throws {
            let gate = ConnectionAdmission(
                capacity: ConnectionAdmission.Capacity(total: 1, perHost: 1_000)
            )
            let identity = try DevTLSIdentity.selfSigned()
            let configuration = TransportConfiguration(
                port: 0,
                backbone: .portableTLS,
                tls: identity
            )
            let transport = PortableTLSTransport(configuration: configuration)
            let stream = try await transport.start(admission: gate)
            let port = transport.boundPort
            #expect(port != 0)

            let accepted = AcceptCollector()
            let collector = Task { await accepted.drain(stream) }

            // A bare TCP connect: the handshake never starts, so the connection is never surfaced.
            let stalled = Self.openStalledConnection(to: port)
            defer { close(stalled) }
            #expect(stalled >= 0)

            // The accept thread charges the slot as soon as `accept(2)` returns, so the count moves
            // without anything being yielded. Poll rather than sleep a fixed span.
            var charged = false
            for _ in 0 ..< 200 where !charged {
                if gate.counts.total == 1 {
                    charged = true
                    break
                }
                try await Task.sleep(for: .milliseconds(10))
            }
            #expect(charged, "a connection stalled before its ClientHello was never charged")
            #expect(gate.isSaturated, "the ceiling did not latch on a handshaking connection")
            #expect(
                accepted.probe.isEmpty,
                "a connection was surfaced before its handshake completed"
            )

            collector.cancel()
            await transport.shutdown()
            _ = await collector.value
        }

        /// Opens a blocking loopback TCP connection to `port` and sends nothing.
        private static func openStalledConnection(to port: UInt16) -> Int32 {
            // Glibc vends SOCK_STREAM as the C enum `__socket_type` while `socket` takes Int32.
            #if canImport(Glibc)
                let descriptor = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
            #else
                let descriptor = socket(AF_INET, SOCK_STREAM, 0)
            #endif
            guard descriptor >= 0 else {
                return -1
            }
            var address = sockaddr_in()
            #if canImport(Darwin)
                address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            #endif
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.bigEndian
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let connected = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
                }
            }
            guard connected else {
                close(descriptor)
                return -1
            }
            return descriptor
        }
    }

#endif
