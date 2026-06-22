//
//  TransportTests.swift
//  HTTPTransportTests
//
//  RED→GREEN driver for the transport abstraction: backbone selection and the in-memory fake.
//

import Testing

@testable import HTTPTransport

@Suite("Transport abstraction & backbone selection")
struct TransportTests {

    @Test("the factory wires each real backbone flag to its implementation")
    func factorySelectsBackbone() {
        for backbone in TransportBackbone.allCases where backbone != .fake {
            let configuration = TransportConfiguration(port: 0, backbone: backbone)
            #expect(TransportFactory.make(configuration).backbone == backbone)
        }
    }

    @Test("FakeTransport yields its seeded connections in order")
    func fakeTransportYieldsConnections() async throws {
        let transport = FakeTransport(connections: [
            FakeConnection(id: TransportConnectionID(1)),
            FakeConnection(id: TransportConnectionID(2)),
        ])
        var ids: [TransportConnectionID] = []
        for await connection in try await transport.start() {
            ids.append(connection.id)
        }
        #expect(ids == [TransportConnectionID(1), TransportConnectionID(2)])
    }

    @Test("FakeConnection delivers inbound bytes then EOF, and records sent bytes")
    func fakeConnectionRoundTrip() async throws {
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array("ping".utf8))
        let chunk = try await connection.receive(maxLength: 16)
        #expect(chunk.map { String(decoding: $0, as: UTF8.self) } == "ping")

        let eof = try await connection.receive(maxLength: 16)
        #expect(eof == nil)

        try await connection.send(Array("pong".utf8))
        let sent = await connection.sentBytes()
        #expect(String(decoding: sent, as: UTF8.self) == "pong")
    }
}
