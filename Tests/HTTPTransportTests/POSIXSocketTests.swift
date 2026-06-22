//
//  POSIXSocketTests.swift
//  HTTPTransportTests
//
//  Audit T-F1 — a write() to a peer that has closed its read end MUST NOT raise SIGPIPE and kill the
//  server process (a one-packet remote DoS). POSIX.1-2017 write(2) delivers SIGPIPE by default;
//  Darwin's SO_NOSIGPIPE socket option converts it to an EPIPE error return so the byte path fails
//  closed. These tests prove the option is applied (so writes return EPIPE, never SIGPIPE).
//

import Darwin
import Testing

@testable import HTTPTransport

@Suite("T-F1 — SO_NOSIGPIPE: a write to a closed peer returns EPIPE, never SIGPIPE")
struct POSIXSocketTests {

    @Test("setNoSIGPIPE: write() to a closed peer returns EPIPE, never SIGPIPE")
    func writeAfterPeerCloseReturnsEPIPE() {
        var fds = [Int32](repeating: 0, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { close(fds[0]) }

        POSIXSocket.setNoSIGPIPE(fds[0])
        close(fds[1])  // the peer closes its read end

        // Without SO_NOSIGPIPE this loop would deliver SIGPIPE and terminate the test process; with
        // it, the kernel reports EPIPE on the write that first notices the peer is gone.
        let payload = [UInt8](repeating: 0x41, count: 4096)
        var sawEPIPE = false
        for _ in 0..<256 {
            let written = payload.withUnsafeBytes { write(fds[0], $0.baseAddress, $0.count) }
            if written < 0 {
                #expect(errno == EPIPE)
                sawEPIPE = true
                break
            }
        }
        #expect(sawEPIPE, "a write to the closed peer must surface EPIPE (SO_NOSIGPIPE active)")
    }

    @Test("makeListenSocket sets SO_NOSIGPIPE on the listening descriptor")
    func listenSocketSuppressesSIGPIPE() throws {
        let (fd, _) = try POSIXSocket.makeListenSocket(
            host: "127.0.0.1", port: 0, nonBlocking: true)
        defer { close(fd) }

        var value: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        #expect(getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, &length) == 0)
        #expect(value == 1)
    }
}
