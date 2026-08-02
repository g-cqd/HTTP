//
//  QUICPeerAttributionTests.swift
//  HTTPTransportTests
//
//  Peer attribution for the QUIC backbones: the address a ``QUICConnection`` reports must be the
//  *peer's*, because it is what the shared admission gate keys its per-host bucket on and what
//  `RateLimitIdentity.peerAddress` keys a request's budget on. Both backbones once reported the
//  listener's own bind address, which collapsed every HTTP/3 client into a single bucket (CWE-770:
//  the per-client ceiling stops bounding anything per client).
//
//  Two genuinely distinct loopback peers are needed to see the difference, and a second loopback
//  literal is not available — macOS binds only `127.0.0.1` on `lo0` unless an alias is added with
//  `ifconfig`, which a test cannot require. The dual-stack listener supplies them instead: a client
//  over `127.0.0.1` and a client over `::1` are two different hosts to the gate.
//
//  Standards: QUIC (RFC 9000 §5.1, connections identified per peer); ALPN "h3" (RFC 7301, RFC 9114
//  §3.1). Defense: CWE-770 (allocation without limits) via the per-host connection ceiling.
//
//  Darwin-only, and excluded from the Linux build by `darwinOnlyTransportTestSources`: every case
//  here needs a Network.framework QUIC listener, a real `NWConnection` h3 client, or the
//  `NWEndpoint` overload of `QUICPeer.address(of:)` — none of which exist on Linux, where there is
//  no QUIC backbone to attribute a peer for. The part of the contract that is NOT about
//  Network.framework — that an unattributable peer folds into one shared, capped, unforgeable
//  admission bucket — lives in `QUICPeerAdmissionTests` and stays cross-platform.
//

import Foundation
import HTTPCore
import HTTPTestSupport
import Network
import Testing

@testable import HTTPTransport

@Suite("QUIC peer attribution", .realNetwork)
struct QUICPeerAttributionTests {
    /// The two loopback peers the dual-stack listener can tell apart.
    private static let peerHosts = ["127.0.0.1", "::1"]

    @Test(
        "two h3 peers occupy two per-host admission buckets",
        .timeLimit(.minutes(1)),
        arguments: ["legacy", "modern"]
    )
    func peersGetSeparateBuckets(backbone: String) async throws {
        guard let transport = try Self.makeTransport(backbone) else {
            return  // modern backbone unavailable on this OS
        }
        let admission = ConnectionAdmission(
            capacity: ConnectionAdmission.Capacity(total: 64, perHost: 64)
        )
        let (accepted, clients) = try await Self.accept(transport, admission: admission)
        defer {
            for client in clients {
                client.cancel()
            }
            Task { await transport.shutdown() }
        }

        #expect(admission.counts.total == 2, "both peers should hold a slot")
        // The defect: both connections hash to one bucket, so a 1,024 per-client ceiling throttles
        // every h3 client collectively instead of throttling each one.
        #expect(admission.counts.hosts == 2)
        #expect(accepted.count == 2)
    }

    @Test(
        "an h3 connection reports the peer's address, not the listener's",
        .timeLimit(.minutes(1)),
        arguments: ["legacy", "modern"]
    )
    func peerIsNotTheBindAddress(backbone: String) async throws {
        guard let transport = try Self.makeTransport(backbone) else {
            return  // modern backbone unavailable on this OS
        }
        let (accepted, clients) = try await Self.accept(transport, admission: nil)
        let boundPort = transport.boundPort
        defer {
            for client in clients {
                client.cancel()
            }
            Task { await transport.shutdown() }
        }

        let peers = accepted.map(\.peer)
        // Two peers dialled from two different loopback addresses must be reported as two different
        // hosts, and neither may be the wildcard the listener bound — that is what proves the address
        // came from the peer rather than from the listener. The exact literals are left to the
        // stack: on a dual-stack listener an IPv4 peer may be reported IPv4-mapped (RFC 4291 §2.5.5.2).
        #expect(Set(peers.map(\.host)).count == 2)
        #expect(peers.allSatisfy { $0.host != "::" && !$0.host.isEmpty })
        // Nor is it the listener's port: each peer speaks from its own ephemeral source port.
        #expect(peers.allSatisfy { $0.port != boundPort && $0.port != 0 })
    }

    @Test(
        "a peer with no reportable address is fail-closed, not a plausible one",
        arguments: [
            nil,
            NWEndpoint.service(name: "q", type: "_quic._udp", domain: "local", interface: nil),
            NWEndpoint.unix(path: "/tmp/quic-peer-attribution.sock")
        ] as [NWEndpoint?]
    )
    func unattributablePeerIsFailClosed(endpoint: NWEndpoint?) {
        let address = QUICPeer.address(of: endpoint)
        #expect(address == QUICPeer.unattributed)
        // Not mistaken for a real address: nothing can parse it as an IP, so `RateLimitIdentity`
        // folds it into the same shared, fail-closed budget it already uses for a missing peer.
        #expect(address.ipAddress == nil)
        #expect(address.host == "-")
    }

    // MARK: - Harness

    /// The backbone under test, or `nil` when this OS cannot provide it.
    private static func makeTransport(_ backbone: String) throws -> (any QUICServerTransport)? {
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        // The IPv6 wildcard (RFC 4291 §2.5.2), not `127.0.0.1`, because this suite needs ONE listener
        // that two peers from two different loopback addresses can both reach. That used to work with
        // a loopback host purely because the QUIC backbones ignored `TransportConfiguration.host`
        // (audit F-04/F-05): they bound every interface whatever they were told. Now the host is
        // honoured, so a test that wants every interface has to say so.
        let configuration = TransportConfiguration(
            host: "::",
            port: 0,
            backbone: .networkFramework,
            tls: tls
        )
        guard backbone == "modern" else {
            return LegacyQUICTransport(configuration: configuration)
        }
        guard #available(macOS 26, iOS 26, *) else {
            return nil
        }
        return ModernQUICTransport(configuration: configuration)
    }

    /// Starts `transport` and connects one client per loopback family, returning both sides.
    ///
    /// Both are returned, and both matter to the caller: a released ``QUICConnection`` returns its
    /// admission slot, and a cancelled client tears the server's connection down — so the caller
    /// holds them for as long as it is asserting about the gate's counts.
    private static func accept(
        _ transport: any QUICServerTransport,
        admission: ConnectionAdmission?
    ) async throws -> (accepted: [any QUICConnection], clients: [NWConnection]) {
        let connections = try await transport.start(admission: admission)
        let port = transport.boundPort
        var clients: [NWConnection] = []
        for host in peerHosts {
            clients.append(try await Self.client(to: host, port: port))
        }
        // The transport yields into an unbounded buffer, so the handshakes above have already been
        // accepted and charged; this only drains what is waiting.
        var accepted: [any QUICConnection] = []
        for await connection in connections {
            accepted.append(connection)
            if accepted.count == peerHosts.count {
                break
            }
        }
        return (accepted, clients)
    }

    /// A QUIC client that has completed its handshake against the loopback listener.
    private static func client(to host: String, port: UInt16) async throws -> NWConnection {
        let options = NWProtocolQUIC.Options(alpn: ["h3"])
        // The dev identity is self-signed: accept it for this loopback test only.
        sec_protocol_options_set_verify_block(
            options.securityProtocolOptions,
            { _, _, complete in complete(true) },
            DispatchQueue(label: "quic.peer.verify")
        )
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any,
            using: NWParameters(quic: options)
        )
        let resumed = OnceLatch()
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                    case .ready where resumed.take():
                        continuation.resume()
                    case .failed(let error) where resumed.take():
                        continuation.resume(throwing: error)
                    default:
                        break
                }
            }
            connection.start(queue: DispatchQueue(label: "quic.peer.client"))
        }
        return connection
    }
}
