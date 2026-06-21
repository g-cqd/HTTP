//
//  SwiftSystemTransportTests.swift
//  HTTPTransportTests
//
//  Loopback integration test for the apple/swift-system backbone (POSIX sockets + FileDescriptor).
//

import Testing

@testable import HTTPTransport

@Suite("swift-system backbone — loopback I/O")
struct SwiftSystemTransportTests {

    @Test("accepts a connection and round-trips bytes over loopback")
    func loopbackRoundTrip() async throws {
        let transport = SwiftSystemTransport(
            configuration: TransportConfiguration(port: 0, backbone: .swiftSystem))
        let stream = try await transport.start()
        try await assertLoopbackEcho(stream: stream, port: transport.boundPort)
        await transport.shutdown()
    }
}
