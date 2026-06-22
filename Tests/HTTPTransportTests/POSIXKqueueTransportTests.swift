//
//  POSIXKqueueTransportTests.swift
//  HTTPTransportTests
//
//  Loopback integration test for the BSD-sockets + hand-rolled kqueue event-loop backbone.
//

import Testing

@testable import HTTPTransport

@Suite("POSIX + kqueue backbone — loopback I/O")
struct POSIXKqueueTransportTests {

    @Test("accepts a connection and round-trips bytes over loopback", .timeLimit(.minutes(1)))
    func loopbackRoundTrip() async throws {
        let transport = POSIXKqueueTransport(
            configuration: TransportConfiguration(port: 0, backbone: .posixKqueue))
        let stream = try await transport.start()
        try await assertLoopbackEcho(stream: stream, port: transport.boundPort)
        await transport.shutdown()
    }
}
