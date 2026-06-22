//
//  POSIXDispatchTransportTests.swift
//  HTTPTransportTests
//
//  Loopback integration test for the BSD-sockets + GCD (DispatchSource / DispatchIO) backbone.
//

import Testing

@testable import HTTPTransport

@Suite("POSIX + Dispatch backbone — loopback I/O")
struct POSIXDispatchTransportTests {

    @Test("accepts a connection and round-trips bytes over loopback", .timeLimit(.minutes(1)))
    func loopbackRoundTrip() async throws {
        let transport = POSIXDispatchTransport(
            configuration: TransportConfiguration(port: 0, backbone: .posixDispatch))
        let stream = try await transport.start()
        try await assertLoopbackEcho(stream: stream, port: transport.boundPort)
        await transport.shutdown()
    }
}
