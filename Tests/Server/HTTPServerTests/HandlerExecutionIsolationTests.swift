//
//  HandlerExecutionIsolationTests.swift
//  HTTPServerTests
//
//  The executable proof of audit CR-F7: one blocking handler must not stall an unrelated connection
//  sharded onto the same reactor.
//
//  Two loopback connections are forced onto ONE event loop (`TransportConfiguration(eventLoopCount:
//  1)`, the kqueue/epoll shard count), so the server hands both serve tasks the *same* serial
//  `TaskExecutor`. Connection A's handler then blocks its thread on a gate — `Thread.sleep`-shaped
//  work: a filesystem call, a synchronous compression pass, a `libcrypto` verify, a logging sink. B's
//  request is written afterwards and must be answered while A is still blocked.
//
//  This test is DELIBERATELY policy-scoped to `.concurrent`, because under `.inline` it cannot pass:
//  A's handler owns the one reactor thread, so B's readiness is never even processed. Measured on
//  this branch by flipping the policy and rerunning — `.concurrent` answers B in 33 ms; `.inline`
//  leaves B with an EMPTY read for the whole 20-second receive timeout. That contrast IS the finding,
//  and scoping the test to the policy is what makes it a proof rather than an assertion. The time
//  limit is the backstop that turns the `.inline` shape into a failure rather than a hung suite.
//
//  Standards: RFC 9110 §7.6 (connection independence — a response on one connection is not ordered
//  against another); the blocking-work hazard is CWE-410 (insufficient resource pool).
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

@Suite("Handler execution — a blocking handler does not stall a sibling connection (CR-F7)")
struct HandlerExecutionIsolationTests {
    /// Event-loop backbones only: they are the ones with a serial `preferredTaskExecutor` to share.
    static let loopBackbones: [TransportBackbone] = {
        #if canImport(Darwin)
            [.posixKqueue]
        #else
            [.posixEpoll]
        #endif
    }()

    @Test(
        "under .concurrent, a blocked handler on one connection does not delay another on its loop",
        .timeLimit(.minutes(1)),
        arguments: loopBackbones
    )
    func blockingHandlerDoesNotStallSibling(_ backbone: TransportBackbone) async throws {
        // A hard thread block, not an `await`: `AsyncGate` would suspend the task and free the
        // reactor, which is precisely the failure mode this test must NOT accidentally model.
        let released = ThreadGate()
        let entered = AsyncEventProbe<String>()
        let responder = ClosureResponder { request, _, _ in
            guard request.path == "/block" else {
                return .text("fast")
            }
            entered.record("blocked")
            released.waitUntilOpen()
            return .text("slow")
        }

        // One loop: both connections are pinned to the same serial executor (audit CR-F7).
        let transport = try TransportFactory.make(
            TransportConfiguration(port: 0, backbone: backbone, eventLoopCount: 1)
        )
        let server = HTTPServer(
            transport: transport,
            responder: responder,
            handlerExecution: .concurrent
        )
        let running = Task { try await server.run() }
        defer {
            running.cancel()
            released.open()
        }
        try await settle { transport.boundPort != 0 }
        let port = transport.boundPort

        let blocking = try Self.openSocket(to: port)
        let sibling = try Self.openSocket(to: port)
        defer {
            close(blocking)
            close(sibling)
        }

        Self.writeRequest(Self.request(for: "/block"), to: blocking)
        _ = try await entered.wait(forAtLeast: 1)

        // The handler on `blocking` is now holding a thread. Under `.inline` that thread is the only
        // reactor, so this request is never even read.
        Self.writeRequest(Self.request(for: "/fast"), to: sibling)
        let answer = Self.readResponse(from: sibling)
        #expect(
            answer.contains("fast"),
            "the sibling connection was not answered while a handler blocked its reactor"
        )

        released.open()
        #expect(Self.readResponse(from: blocking).contains("slow"))
        await server.shutdown()
    }

    // MARK: - Helpers

    /// A one-shot `GET path` that closes the connection, so the client reads to EOF.
    private static func request(for path: String) -> String {
        "GET \(path) HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    }

    /// Opens a blocking loopback TCP connection to `port`, returning its descriptor.
    private static func openSocket(to port: UInt16) throws -> Int32 {
        // Glibc vends SOCK_STREAM as the C enum `__socket_type` while `socket` takes Int32.
        #if canImport(Glibc)
            let descriptor = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #else
            let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        #endif
        try #require(descriptor >= 0)
        var address = sockaddr_in()
        #if canImport(Darwin)
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        try #require(connected, "could not connect to the bound port")
        return descriptor
    }

    private static func writeRequest(_ request: String, to descriptor: Int32) {
        let bytes = Array(request.utf8)
        _ = bytes.withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, 0) }
    }

    /// Reads until the peer closes (`Connection: close`) or the receive timeout expires.
    private static func readResponse(from descriptor: Int32) -> String {
        var timeout = timeval(tv_sec: 20, tv_usec: 0)
        setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
        var out: [UInt8] = []
        var scratch = [UInt8](repeating: 0, count: 4_096)
        while true {
            let count = scratch.withUnsafeMutableBytes {
                recv(descriptor, $0.baseAddress, $0.count, 0)
            }
            guard count > 0 else {
                break
            }
            out.append(contentsOf: scratch[0 ..< count])
        }
        return String(decoding: out, as: Unicode.UTF8.self)
    }
}
