//
//  POSIXSocketTests.swift
//  HTTPTransportTests
//
//  Per-connection socket options the BSD-socket backbones set on every accepted descriptor:
//  • SO_NOSIGPIPE (audit T-F1) — a write() to a peer that closed its read end MUST return EPIPE, not
//    raise SIGPIPE and kill the process (a one-packet remote DoS); Darwin's SO_NOSIGPIPE converts it.
//  • TCP_NODELAY — Nagle's algorithm disabled so a sub-MSS response flushes immediately instead of
//    coalescing, which inflates tail latency on small / keep-alive responses (the p99.9 Bench/ shows).
//  These tests prove each option is actually applied to the descriptor.
//

import Darwin
import Testing

@testable import HTTPTransport

@Suite("POSIXSocket per-connection options — SO_NOSIGPIPE (T-F1) and TCP_NODELAY")
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
        let payload = [UInt8](repeating: 0x41, count: 4_096)
        var sawEPIPE = false
        for _ in 0 ..< 256 {
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
            host: "127.0.0.1",
            port: 0,
            nonBlocking: true,
            backlog: 128
        )
        defer { close(fd) }

        var value: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        #expect(getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, &length) == 0)
        #expect(value == 1)
    }

    @Test("setNoDelay sets TCP_NODELAY (Nagle disabled) on a TCP socket")
    func setNoDelayDisablesNagle() {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #expect(fd >= 0)
        defer { close(fd) }

        POSIXSocket.setNoDelay(fd)

        var value: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        #expect(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, &length) == 0)
        // macOS reports the internal TCP flag (TF_NODELAY = 4), not a normalized 1 — non-zero is
        // "enabled", so assert enabled rather than a specific value.
        #expect(value != 0, "TCP_NODELAY must be enabled (Nagle off so small responses flush)")
    }

    @Test("makeListenSocket honors a custom backlog (listen succeeds)")
    func listenSocketAcceptsCustomBacklog() throws {
        let (fd, port) = try POSIXSocket.makeListenSocket(
            host: "127.0.0.1",
            port: 0,
            nonBlocking: true,
            backlog: 2_048
        )
        defer { close(fd) }
        #expect(fd >= 0)
        #expect(port > 0)
    }
}
