//
//  DeflateAllocationTests.swift
//  HTTPDeflateTests
//
//  The allocation oracle (`expectAllocations` over the CHTTPTestMalloc counter): after warm-up,
//  pumping chunks through the span-shaped core allocates NOTHING in either direction — every
//  buffer, table, and scratch was fixed at init. Exact ONLY in release: at `-Onone` every safe
//  array write pays a heap-allocated `_modify` coroutine frame (measured: ~1 malloc per octet,
//  disappearing entirely at `-O`), so the zero assertion is release-gated and the debug leg still
//  drives the same steady-state path for its side effects.
//

internal import HTTPTestSupport
import Testing

@testable internal import HTTPDeflate

@Suite("Allocation oracles — zero steady-state allocations per chunk", .serialized)
struct DeflateAllocationTests {
    /// Whether this build can meet the exact-zero contract (see the file header).
    private var exact: Bool {
        #if DEBUG
            false
        #else
            true
        #endif
    }

    @Test("deflate: chunked span pumping allocates nothing after warm-up (exact in release)")
    func deflateSteadyState() {
        var deflator = Deflator()
        let payload = DeflateCorpus.text(600_000)
        var sink = [UInt8](repeating: 0, count: 1 << 17)
        var offset = 0
        let step = 4_096
        // Warm-up: first blocks, lazy paths, window slide, and the writer's first drains.
        pump(&deflator, payload, &sink, &offset, chunks: 80, step: step)
        let measured = mallocDelta {
            pump(&deflator, payload, &sink, &offset, chunks: 40, step: step)
        }
        if exact, let measured {
            #expect(measured == 0, "steady-state deflate must not allocate (measured \(measured))")
        }
        #expect(offset == 120 * step, "the measured region must actually pump input")
    }

    @Test("inflate: chunked span pumping allocates nothing after warm-up (exact in release)")
    func inflateSteadyState() {
        // Incompressible noise so the coded stream is large enough that the measured region does
        // real symbol work (compressible text would be fully consumed during warm-up).
        var generator = SeededRNG(seed: Seed.named("httpdeflate.alloc.inflate"))
        let payload = DeflateCorpus.random(400_000, using: &generator)
        var deflator = Deflator()
        var coded: [UInt8] = []
        _ = deflator.pump(payload, appendingTo: &coded, flush: .finish)
        #expect(coded.count > 300_000, "the fixture must stay incompressible")
        var inflator = Inflator()
        var sink = [UInt8](repeating: 0, count: 1 << 17)
        var offset = 0
        let step = 4_096
        inflate(&inflator, coded, &sink, &offset, chunks: 30, step: step)
        let measured = mallocDelta {
            inflate(&inflator, coded, &sink, &offset, chunks: 30, step: step)
        }
        if exact, let measured {
            #expect(measured == 0, "steady-state inflate must not allocate (measured \(measured))")
        }
        #expect(offset == 60 * step, "the measured region must actually pump input")
    }

    /// Feeds `chunks` × `step` octets of `payload` from `offset`, discarding output into `sink`.
    private func pump(
        _ deflator: inout Deflator,
        _ payload: [UInt8],
        _ sink: inout [UInt8],
        _ offset: inout Int,
        chunks: Int,
        step: Int
    ) {
        SpanBridge.withSpan(of: payload) { input in
            for _ in 0 ..< chunks {
                let end = min(offset + step, payload.count)
                var index = 0
                let slice = input.extracting(offset ..< end)
                var progress = CodecProgress.needsOutput
                while progress == .needsOutput {
                    _ = SpanBridge.withOutputSpan(of: &sink) { span in
                        progress = deflator.run(input: slice, from: &index, into: &span)
                    }
                }
                offset = end
            }
        }
    }

    /// Inflates `chunks` × `step` coded octets from `offset`, discarding output into `sink`.
    private func inflate(
        _ inflator: inout Inflator,
        _ coded: [UInt8],
        _ sink: inout [UInt8],
        _ offset: inout Int,
        chunks: Int,
        step: Int
    ) {
        SpanBridge.withSpan(of: coded) { input in
            for _ in 0 ..< chunks {
                let end = min(offset + step, coded.count)
                var index = 0
                let slice = input.extracting(offset ..< end)
                var progress = CodecProgress.needsOutput
                while progress == .needsOutput {
                    _ = SpanBridge.withOutputSpan(of: &sink) { span in
                        progress =
                            (try? inflator.run(input: slice, from: &index, into: &span))
                            ?? .finished
                    }
                }
                offset = end
            }
        }
    }
}
