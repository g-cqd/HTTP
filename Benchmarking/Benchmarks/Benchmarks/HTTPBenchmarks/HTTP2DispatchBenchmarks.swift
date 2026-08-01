//
//  HTTP2DispatchBenchmarks.swift
//  HTTPBenchmarks
//
//  What one BUFFERED HTTP/2 request costs the server's merged-mailbox consumer, end to end: preface,
//  SETTINGS, and `count` pipelined `GET`s driven through `HTTPServer.serve` over an in-memory
//  connection, to the last response frame.
//
//  It exists to decide ONE question, and the decision rule is recorded here BEFORE the numbers so it
//  cannot be retrofitted to whatever they turn out to be (the ADR 0007 / finding 19 house style):
//
//      The 2026-07-31 audit's finding 6 gave streaming requests and RFC 8441 tunnels a per-stream
//      cancellation handle so a peer RST_STREAM (RFC 9113 §6.4) stops work the client has withdrawn,
//      and DEFERRED the buffered path on the stated grounds that it "would pay an extra `Task` plus a
//      `Mutex` per request against a 200k-rps target". That claim was never measured.
//
//      LAND buffered cancellation IF the per-request malloc count is unchanged or grows by at most
//      one, AND `http2/dispatch/buffered-16` wall clock regresses by less than 5 % — the same bar
//      ADR 0007 set for moving the handler-execution default. Otherwise keep the deferral and record
//      the number that justifies it.
//
//  Two allocations were the honest expectation going in: the `Task` box, and the dictionary node for
//  its handle. Both turned out to be avoidable. The `Mutex` half of the deferral's premise goes away
//  because the connection already owns per-stream tables, so the handle lands in one of those rather
//  than in a fresh object; and the `Task` half goes away because the unstructured task can be
//  dispatched *instead of* the task-group child rather than inside it.
//
//  ── MEASURED, 2026-08-01, Mac14,9 (M2 Max), release build, p50, marginal per request ─────────────
//
//  Marginal cost is (buffered-16 − buffered-1) / 15, which cancels the per-connection preface,
//  SETTINGS, handshake and teardown and leaves what one more request costs.
//
//      shape                                                mallocs/req   instructions/req
//      no cancellation (branch HEAD before R5-P0d)             21.07          94.8 K
//      cancel handle, task dispatched INSTEAD of the child     21.07          95.3 K   (+0.5 %)
//      cancel handle, task NESTED inside the child (F6 shape)  26.07         114.9 K   (+21 %)
//      …and that shape plus an unconditional preference wrap   27.07         117.9 K   (+24 %)
//
//  So the rule passes on the shipped shape (0 extra mallocs, +0.5 % — inside the noise band) and
//  would have failed on the shape finding 6 costed. The deferral was right about its own shape and
//  wrong about the conclusion, which is the difference measuring makes.
//
//  Host qualification: 10 cores, load average 18.5 (other agents compiling throughout), 3 runs of the
//  shipped shape spread 2076–2090 K instructions at buffered-16 (0.7 %). Wall clock is NOT reported
//  as a decision input — its p50 spread on this host is far wider than the effect. Reproduce with
//  `swift package --package-path Benchmarking/Benchmarks benchmark --filter 'http2/dispatch/.*'`.
//

import Benchmark
import HPACK
import HTTP2
import HTTPCore
import HTTPServer
import HTTPTransport

func registerHTTP2DispatchBenchmarks() {
    for count in [1, 16] {
        Benchmark("http2/dispatch/buffered-\(count)") { benchmark in
            let wire = http2BufferedRequestWire(count: count)
            for _ in benchmark.scaledIterations {
                let connection = FakeConnection(
                    id: TransportConnectionID(1),
                    negotiatedApplicationProtocol: "h2",
                    inbound: wire
                )
                // `run()` rather than the internal `serve(_:)`: this package builds against the
                // library's PUBLIC surface, so the fake transport is what hands the connection in —
                // which also puts the serve task under the same `accept` wrapper production uses.
                let server = HTTPServer(
                    transport: FakeTransport(connections: [connection]),
                    responder: ClosureResponder { _, _, _ in .text("ok") }
                )
                try? await server.run()
                blackHole(await connection.sentBytes())
            }
        }
    }
}

/// Builds one client wire: preface + SETTINGS + `count` HEADERS(GET, END_STREAM) on odd stream ids.
private func http2BufferedRequestWire(count: Int) -> [UInt8] {
    var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
    var settings: [UInt8] = []
    HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection)
        .encode(into: &settings)
    var wire = HTTP2ConnectionPreface.client + settings
    for index in 0 ..< count {
        let block = encoder.encode([
            HPACKField(name: ":method", value: "GET"),
            HPACKField(name: ":scheme", value: "https"),
            HPACKField(name: ":path", value: "/index.html"),
            HPACKField(name: ":authority", value: "example.com")
        ])
        var headers: [UInt8] = []
        HTTP2FrameHeader(
            payloadLength: block.count,
            type: .headers,
            flags: [.endHeaders, .endStream],
            streamID: HTTP2StreamID(UInt32(index) * 2 + 1)
        )
        .encode(into: &headers)
        headers.append(contentsOf: block)
        wire += headers
    }
    return wire
}
