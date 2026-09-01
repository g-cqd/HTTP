//
//  StaticFileExecutionPlacementTests.swift
//  HTTPServerTests
//
//  Where static-file blocking work actually runs (ADR 0008). The performance addendum lists path
//  walking, `openat`, `fstat`, small-file `pread`, streaming `pread` and directory enumeration as
//  "synchronous inside the handler hierarchy" and therefore able to block a reactor, and asks for a
//  bounded blocking-I/O executor. Before adding one it is worth knowing which of those the *existing*
//  seam already covers, because inferring it from the call graph gets it half right.
//
//  It is half right. `HandlerExecutionPolicy` wraps the `respond` call, so everything `FileResponder`
//  does while answering — the whole `openat`/`fstat` walk, the sidecar probes, the sub-threshold
//  `pread`, the autoindex `readdir`/`fstatat` loop — follows the policy and leaves the reactor under
//  `.concurrent`. The `ResponseStream` producer does not: the hop is scoped to `respond`, the
//  preference is restored when it returns, and the engine drives the producer afterwards. So the
//  streaming `pread` pump — and, since streaming compression landed, the per-chunk deflate with it —
//  stays on the reactor under every policy.
//
//  These two facts are what ADR 0008 decides on, so they are pinned here rather than argued.
//

internal import Foundation
internal import HTTPCore
internal import HTTPTestSupport
internal import HTTPTransport
import Testing

@testable import HTTPServer

/// `.inline` keeps the handler on the reactor; `.concurrent` lifts it off. `.adaptive` is covered by
/// `HandlerExecutionAdaptiveTests` and adds nothing here.
private let placements: [(policy: HandlerExecutionPolicy, handlerOnReactor: Bool)] = [
    (.inline, true), (.concurrent, false)
]

/// A `GET /` over HTTP/1.1 that closes the connection, so `serve` returns once the response is out.
private let getRoot = Array("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".utf8)

/// Serves `connection` under its own preferred executor — the body of `HTTPServer.accept(_:)`.
private func servePinned(
    _ connection: ReactorPinnedConnection,
    _ responder: any HTTPResponder,
    _ policy: HandlerExecutionPolicy
) async {
    let server = HTTPServer(
        transport: FakeTransport(),
        responder: responder,
        handlerExecution: policy
    )
    await withTaskExecutorPreference(connection.preferredTaskExecutor) {
        await server.serve(connection)
    }
}

/// A directory holding one file large enough to stream, and the responder that serves it.
private func fileResponder(streamingAbove threshold: Int) throws -> (any HTTPResponder, URL) {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("placement-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let body = Data(String(repeating: "static file body\n", count: 4_096).utf8)
    try body.write(to: root.appendingPathComponent("index.html"))
    return (FileResponder(root: root.path, streamingThreshold: threshold), root)
}

@Test(
    "ADR 0008 — FileResponder's own blocking work follows HandlerExecutionPolicy",
    arguments: placements
)
func fileHandlerFollowsThePolicy(
    policy: HandlerExecutionPolicy,
    handlerOnReactor: Bool
) async throws {
    let (files, root) = try fileResponder(streamingAbove: 1 << 20)
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = ReactorProbeExecutor()
    let placement = AsyncEventProbe<Bool>()
    // Delegating rather than wrapping: the closure runs in exactly the isolation the policy put the
    // responder chain in, which is the isolation `openat`/`fstat`/`pread` will run in.
    let responder = ClosureResponder { request, body, context in
        await Task.yield()
        placement.record(executor.isCurrent)
        return await files.respond(to: request, body: body, context: context)
    }
    let connection = ReactorPinnedConnection(inbound: getRoot, executor: executor)
    await servePinned(connection, responder, policy)

    #expect(String(decoding: connection.sentBytes, as: Unicode.UTF8.self).hasPrefix("HTTP/1.1 200"))
    #expect(placement.events == [handlerOnReactor])
}

@Test(
    "ADR 0008 — a response-stream producer stays on the reactor under every policy",
    arguments: placements
)
func streamProducerStaysOnTheReactor(
    policy: HandlerExecutionPolicy,
    handlerOnReactor: Bool
) async {
    let executor = ReactorProbeExecutor()
    let handler = AsyncEventProbe<Bool>()
    let producer = AsyncEventProbe<Bool>()
    let responder = ClosureResponder { _, _, _ in
        await Task.yield()
        handler.record(executor.isCurrent)
        let stream = ResponseStream { writer in
            await Task.yield()
            producer.record(executor.isCurrent)
            try await writer.write(Array("streamed".utf8))
        }
        return ServerResponse(HTTPResponse(status: .ok), stream: stream)
    }
    let connection = ReactorPinnedConnection(inbound: getRoot, executor: executor)
    await servePinned(connection, responder, policy)

    #expect(String(decoding: connection.sentBytes, as: Unicode.UTF8.self).hasSuffix("0\r\n\r\n"))
    #expect(handler.events == [handlerOnReactor], "the handler did not follow the policy")
    // The point of the whole file: the producer is NOT covered by the seam. If this ever reads
    // `[false]` under `.concurrent`, the seam grew to cover stream production and ADR 0008's open
    // item is closed — update the ADR rather than the expectation.
    #expect(producer.events == [true], "the stream producer left the reactor")
}
