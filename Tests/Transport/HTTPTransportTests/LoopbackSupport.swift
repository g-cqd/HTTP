//
//  LoopbackSupport.swift
//  HTTPTransportTests
//
//  Shared loopback echo round-trip used by every backbone's integration test, so each backbone is
//  validated against real sockets through the same client.
//

internal import Darwin
internal import Network
import Testing

@testable import HTTPTransport

/// Opens a blocking loopback TCP connection to `port`, returning its descriptor (`-1` on failure).
///
/// A raw descriptor rather than a `TransportConnection`: the accept-path tests need a client the
/// server has *not* accepted yet, which is the state the admission ceiling is about.
func openLoopbackConnection(to port: UInt16) -> Int32 {
    let descriptor = socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else {
        return -1
    }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    let connected = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
        }
    }
    guard connected else {
        Darwin.close(descriptor)
        return -1
    }
    return descriptor
}

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
        guard let connection = await iterator.next() else {
            return
        }
        let chunk = try await connection.receive(maxLength: 64)
        if let chunk {
            try await connection.send(chunk)
        }
        await connection.close()
    }

    let endpointPort = try #require(NWEndpoint.Port(rawValue: port))
    let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
    let bridged = NetworkFrameworkConnection(
        id: TransportConnectionID(0),
        connection: client,
        negotiatedApplicationProtocol: nil,
        isSecure: false
    )
    client.start(queue: .global())

    try await bridged.send(payload)
    let echo = try await bridged.receive(maxLength: 64)
    #expect(echo == payload)

    await bridged.close()
    _ = await server.result
}

/// Drives a **scatter-gather** round-trip: the server side replies via `send(head, body)` (the `writev`
/// path on the POSIX event-loop backbones, the coalescing default elsewhere), and the client must read
/// back `head + body` intact and in order. `body` is sized to force a real two-`iovec` write and a
/// multi-chunk client read.
func assertLoopbackScatterGather(
    stream: AsyncStream<any TransportConnection>,
    port: UInt16,
    head: [UInt8],
    body: [UInt8]
) async throws {
    #expect(port != 0)

    let server = Task {
        var iterator = stream.makeAsyncIterator()
        guard let connection = await iterator.next() else {
            return
        }
        _ = try await connection.receive(maxLength: 64)  // consume the client's hello
        try await connection.send(head, body)  // scatter-gather: head then body, one logical send
        await connection.close()
    }

    let endpointPort = try #require(NWEndpoint.Port(rawValue: port))
    let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
    let bridged = NetworkFrameworkConnection(
        id: TransportConnectionID(0),
        connection: client,
        negotiatedApplicationProtocol: nil,
        isSecure: false
    )
    client.start(queue: .global())

    try await bridged.send(Array("hello".utf8))
    let expected = head + body
    var received: [UInt8] = []
    while received.count < expected.count {
        guard let chunk = try await bridged.receive(maxLength: 4_096), !chunk.isEmpty else {
            break
        }
        received.append(contentsOf: chunk)
    }
    #expect(received == expected)

    await bridged.close()
    _ = await server.result
}

/// Drives a **file-region** round-trip (G5): the server side replies via
/// `sendFile(descriptor:offset:length:)` — kernel `sendfile(2)` on the POSIX event-loop backbones,
/// the copying `pread` default elsewhere — and the client must read back exactly
/// `expected` (`payload[offset...]`, proving the offset plumbing, not just whole-file).
func assertLoopbackSendFile(
    stream: AsyncStream<any TransportConnection>,
    port: UInt16,
    file: Int32,
    offset: Int,
    expected: [UInt8]
) async throws {
    #expect(port != 0)

    let length = expected.count
    let server = Task {
        var iterator = stream.makeAsyncIterator()
        guard let connection = await iterator.next() else {
            return
        }
        _ = try await connection.receive(maxLength: 64)  // consume the client's hello
        try await connection.sendFile(descriptor: file, offset: offset, length: length)
        await connection.close()
    }

    let endpointPort = try #require(NWEndpoint.Port(rawValue: port))
    let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
    let bridged = NetworkFrameworkConnection(
        id: TransportConnectionID(0),
        connection: client,
        negotiatedApplicationProtocol: nil,
        isSecure: false
    )
    client.start(queue: .global())

    try await bridged.send(Array("hello".utf8))
    var received: [UInt8] = []
    while received.count < expected.count {
        guard let chunk = try await bridged.receive(maxLength: 16_384), !chunk.isEmpty else {
            break
        }
        received.append(contentsOf: chunk)
    }
    #expect(received == expected)

    await bridged.close()
    _ = await server.result
}
