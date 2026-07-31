//
//  AcceptBackpressureTests.swift
//  HTTPTransportTests
//
//  Accept-time backpressure across the POSIX backbones (audit F8). Two distinct behaviors are pinned
//  against real loopback sockets, because the whole point of the finding is that the ceiling must bite
//  at `accept(2)` and not after a task has been spawned:
//
//   - The GLOBAL ceiling suspends the listener. A saturated transport stops re-arming its accept
//     source entirely, so the excess connections stay in the kernel's `listen(2)` backlog instead of
//     being drained into an unbounded queue; freeing slots re-arms it and the backlog drains.
//   - The PER-HOST ceiling does not. A refused connection is closed at the accept point — the client
//     sees EOF rather than hanging — while the listener keeps draining, so one abusive source cannot
//     deny service to everyone else.
//
//  Standards: `accept(2)`/`listen(2)` per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP (RFC 9293) over
//  IPv4 (RFC 791). A resource-exhaustion defense in the spirit of RFC 9110 §15.5.30 (429) — CWE-770,
//  CWE-400.
//

internal import Darwin
import HTTPTestSupport
import Synchronization
import Testing

@testable import HTTPTransport

@Suite("Accept backpressure — the ceiling bites at accept(2) (audit F8)")
struct AcceptBackpressureTests {
    /// The backbones whose accept loops route through the shared `AcceptGate` on this platform.
    ///
    /// `.posixEpoll` is the Linux mirror of `.posixKqueue` and compiles to nothing here, so it cannot
    /// be exercised on Darwin; it shares the same accept-loop shape and gate.
    static let gatedBackbones: [TransportBackbone] = [.posixKqueue, .posixDispatch, .swiftSystem]

    @Test(
        "at the global ceiling the transport stops accepting, and resumes when slots free",
        .timeLimit(.minutes(1)),
        arguments: gatedBackbones
    )
    func suspendsAtCapacityAndResumes(_ backbone: TransportBackbone) async throws {
        let capacity = 4
        let gate = ConnectionAdmission(
            capacity: ConnectionAdmission.Capacity(total: capacity, perHost: 1_000)
        )
        let transport = try Self.makeTransport(backbone)
        let stream = try await transport.start(admission: gate)
        let port = transport.boundPort
        #expect(port != 0)

        let accepted = AcceptCollector()
        let collector = Task { await accepted.drain(stream) }
        let clients = (0 ..< capacity * 2).map { _ in Self.connect(to: port) }
        defer {
            for client in clients {
                Darwin.close(client)
            }
        }

        _ = try await accepted.probe.wait(forAtLeast: capacity)
        // Settle: if the transport were still draining into the stream, the extra four would land here.
        // A negative ("nothing more arrives") cannot be awaited on a probe, so this is a bounded wait.
        try await Task.sleep(for: .milliseconds(300))
        #expect(accepted.probe.count == capacity, "the accept stream carried more than the ceiling")
        #expect(gate.counts.total == capacity)
        #expect(gate.isSaturated, "the gate must be latched so the transport stays suspended")

        // Free every slot: the gate crosses its hysteresis watermark and re-arms the accept source,
        // which then drains the four connections still sitting in the listen(2) backlog.
        await accepted.releaseAll()
        _ = try await accepted.probe.wait(forAtLeast: capacity * 2)
        #expect(accepted.probe.count >= capacity * 2)

        collector.cancel()
        await transport.shutdown()
        _ = await collector.value
    }

    @Test(
        "a per-host rejection is closed at accept time and never yielded, and draining continues",
        .timeLimit(.minutes(1)),
        arguments: gatedBackbones
    )
    func perHostRejectionClosesAtAcceptTime(_ backbone: TransportBackbone) async throws {
        // Every loopback client shares the host "127.0.0.1", so the per-host ceiling is what bites;
        // the global one is far away, which is exactly the case that must NOT suspend the listener.
        let capacity = 4
        let gate = ConnectionAdmission(
            capacity: ConnectionAdmission.Capacity(total: 10_000, perHost: capacity)
        )
        let transport = try Self.makeTransport(backbone)
        let stream = try await transport.start(admission: gate)
        let port = transport.boundPort
        #expect(port != 0)

        let accepted = AcceptCollector()
        let collector = Task { await accepted.drain(stream) }
        let clients = (0 ..< capacity * 2).map { _ in Self.connect(to: port) }
        defer {
            for client in clients {
                Darwin.close(client)
            }
        }

        _ = try await accepted.probe.wait(forAtLeast: capacity)
        try await Task.sleep(for: .milliseconds(300))  // bounded wait: nothing more may be yielded
        #expect(accepted.probe.count == capacity, "a refused connection reached the accept stream")
        #expect(!gate.isSaturated, "a per-host rejection must not suspend the accept source")

        // The four refused connections were closed on the accept loop — their clients see EOF, not a
        // hang, which is the difference between "refused" and "queued forever".
        let eofCount = clients.filter { Self.readsEOF($0) }.count
        #expect(eofCount == capacity, "the refused connections were not closed at accept time")

        collector.cancel()
        await transport.shutdown()
        _ = await collector.value
    }

    // MARK: - Helpers

    private static func makeTransport(_ backbone: TransportBackbone) throws -> any ServerTransport {
        try TransportFactory.make(
            TransportConfiguration(port: 0, backbone: backbone, eventLoopCount: 1)
        )
    }

    /// Opens a blocking loopback TCP connection to `port`, returning its descriptor (`-1` on failure).
    private static func connect(to port: UInt16) -> Int32 {
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

    /// Whether `descriptor` reads end-of-stream within a short receive timeout.
    ///
    /// `read` returning 0 is EOF (the server closed); `-1` with the timeout is a still-open connection.
    private static func readsEOF(_ descriptor: Int32) -> Bool {
        guard descriptor >= 0 else {
            return false
        }
        var timeout = timeval(tv_sec: 0, tv_usec: 300_000)
        setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
        var byte: UInt8 = 0
        return read(descriptor, &byte, 1) == 0
    }
}
