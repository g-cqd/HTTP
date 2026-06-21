//
//  NetworkFrameworkTransportTests.swift
//  HTTPTransportTests
//
//  Loopback integration test for the Network.framework backbone: bind an ephemeral port, connect a
//  client, and round-trip bytes through the accept loop + connection bridge.
//

internal import Network
import Testing

@testable import HTTPTransport

@Suite("Network.framework backbone — loopback I/O")
struct NetworkFrameworkTransportTests {

    @Test("accepts a connection and round-trips bytes over loopback")
    func loopbackRoundTrip() async throws {
        let transport = NetworkFrameworkTransport(
            configuration: TransportConfiguration(port: 0, backbone: .networkFramework))
        let connections = try await transport.start()

        let port = transport.boundPort
        #expect(port != 0)

        // Server side: accept the first connection, receive a chunk, echo it back.
        let server = Task {
            var iterator = connections.makeAsyncIterator()
            guard let connection = await iterator.next() else { return }
            let chunk = try await connection.receive(maxLength: 64)
            if let chunk {
                try await connection.send(chunk)
            }
            await connection.close()
        }

        // Client side: connect, send "ping", read the echo (reusing the connection bridge).
        let endpointPort = try #require(NWEndpoint.Port(rawValue: port))
        let nwClient = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
        let client = NetworkFrameworkConnection(id: TransportConnectionID(0), connection: nwClient)
        nwClient.start(queue: .global())

        try await client.send(Array("ping".utf8))
        let echo = try await client.receive(maxLength: 64)
        #expect(echo.map { String(decoding: $0, as: UTF8.self) } == "ping")

        await client.close()
        _ = await server.result
        await transport.shutdown()
    }
}
