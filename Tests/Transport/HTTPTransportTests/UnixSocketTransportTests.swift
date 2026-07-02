//
//  UnixSocketTransportTests.swift
//  HTTPTransportTests
//
//  The `.unixDomainSocket` backbone (`AF_UNIX`, POSIX.1-2017): binds a filesystem socket path on the
//  platform's event-loop machinery (kqueue here) and round-trips bytes against a raw AF_UNIX client —
//  proving the listener mode end to end — plus the fail-closed paths (missing / over-long path).
//

internal import Darwin
internal import Dispatch
internal import Foundation
import HTTPTestSupport
import Testing

@testable import HTTPTransport

@Suite("Transport — UNIX-domain-socket backbone (AF_UNIX)")
struct UnixSocketTransportTests {
    @Test("accepts a connection at a socket path and round-trips bytes", .timeLimit(.minutes(1)))
    func roundTripsOverSocketPath() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("uds-\(UInt32.random(in: 0 ... .max)).sock").path
        defer { unlink(path) }
        let transport = try TransportFactory.make(
            TransportConfiguration(port: 0, backbone: .unixDomainSocket, unixSocketPath: path)
        )
        #expect(transport.backbone == .unixDomainSocket)
        let stream = try await transport.start()
        #expect(transport.boundPort == 0)  // a UNIX-domain listener has no port

        // Server side: accept one connection, echo the first chunk, report the peer.
        let peerHost = AsyncEventProbe<String>()
        let server = Task {
            var iterator = stream.makeAsyncIterator()
            guard let connection = await iterator.next() else {
                return
            }
            peerHost.record(connection.peer.host)
            if let chunk = try await connection.receive(maxLength: 64) {
                try await connection.send(chunk)
            }
            await connection.close()
        }

        // Client side: a raw blocking AF_UNIX socket on a utility queue (test-only).
        let echoed = AsyncEventProbe<[UInt8]>()
        DispatchQueue.global()
            .async {
                let fd = socket(AF_UNIX, SOCK_STREAM, 0)
                guard fd >= 0 else {
                    return
                }
                defer { close(fd) }
                var address = sockaddr_un()
                address.sun_family = sa_family_t(AF_UNIX)
                let bytes = Array(path.utf8)
                withUnsafeMutableBytes(of: &address.sun_path) { raw in
                    raw.copyBytes(from: bytes)
                    raw[bytes.count] = 0
                }
                let connected = withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
                    }
                }
                guard connected else {
                    return
                }
                let ping = Array("ping".utf8)
                _ = ping.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
                var buffer = [UInt8](repeating: 0, count: 64)
                let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
                if count > 0 {
                    echoed.record(Array(buffer[..<count]))
                }
            }

        let echoes = try await echoed.wait(forAtLeast: 1, timeout: .seconds(10))
        #expect(echoes.first == Array("ping".utf8))
        let peers = try await peerHost.wait(forAtLeast: 1, timeout: .seconds(10))
        #expect(peers.first == path)  // UNIX-domain peers report the socket path as their address
        _ = await server.result
        await transport.shutdown()
    }

    @Test("start() fails closed without a socket path")
    func missingPathFailsClosed() async throws {
        let transport = try TransportFactory.make(
            TransportConfiguration(port: 0, backbone: .unixDomainSocket)
        )
        await #expect(throws: TransportError.self) {
            _ = try await transport.start()
        }
    }

    @Test("an over-long socket path fails closed (sun_path bound)")
    func overlongPathFailsClosed() async throws {
        let path = "/tmp/" + String(repeating: "x", count: 200)  // > sun_path capacity
        let transport = try TransportFactory.make(
            TransportConfiguration(port: 0, backbone: .unixDomainSocket, unixSocketPath: path)
        )
        await #expect(throws: TransportError.self) {
            _ = try await transport.start()
        }
    }
}
