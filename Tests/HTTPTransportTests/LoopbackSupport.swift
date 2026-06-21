//
//  LoopbackSupport.swift
//  HTTPTransportTests
//
//  Shared loopback echo round-trip used by every backbone's integration test, so each backbone is
//  validated against real sockets through the same client.
//

internal import Network
import Testing

@testable import HTTPTransport

/// Drives a loopback echo against a started transport's connection `stream` on `port`.
///
/// The server side accepts one connection and echoes the first chunk; a Network.framework client
/// connects, sends `payload`, and must read it back unchanged.
func assertLoopbackEcho(
    stream: AsyncStream<any TransportConnection>,
    port: UInt16,
    payload: [UInt8] = Array("ping".utf8)
) async throws {
    #expect(port != 0)

    let server = Task {
        var iterator = stream.makeAsyncIterator()
        guard let connection = await iterator.next() else { return }
        let chunk = try await connection.receive(maxLength: 64)
        if let chunk {
            try await connection.send(chunk)
        }
        await connection.close()
    }

    let endpointPort = try #require(NWEndpoint.Port(rawValue: port))
    let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
    let bridged = NetworkFrameworkConnection(id: TransportConnectionID(0), connection: client)
    client.start(queue: .global())

    try await bridged.send(payload)
    let echo = try await bridged.receive(maxLength: 64)
    #expect(echo == payload)

    await bridged.close()
    _ = await server.result
}
