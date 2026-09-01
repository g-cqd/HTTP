//
//  ChunkStabilityTests.swift
//  HTTPDeflateTests
//
//  The pinned property the streamed content coding depends on (see ContentEncoderStreamTests):
//  under `DeflateFlush.none` the coded octets are a function of the input octets alone, never of
//  how they were chunked — so the streamed and buffered codings of one representation are
//  byte-identical. Structural in this codec (matching defers until a full lookahead is visible),
//  but pinned here because it is the property a future optimization is most likely to break.
//

internal import HTTPDeflate
import Testing

@Suite("Chunk stability — output is a function of the octets, not the chunking")
struct ChunkStabilityTests {
    private let chunkings = [1, 7, 100, 1_024, 65_536, Int.max]

    @Test(
        "gzip members are byte-identical across chunk sizes at every level",
        arguments: [.fast, .balanced, .store] as [DeflateLevel]
    )
    func gzipChunkStability(_ level: DeflateLevel) {
        let payload = DeflateCorpus.text(200_000)
        var reference: [UInt8]?
        for chunking in chunkings {
            var encoder = GzipDeflator(level: level)
            var coded: [UInt8] = []
            var offset = 0
            while offset < payload.count {
                let step = chunking == Int.max ? payload.count : chunking
                let end = min(offset + step, payload.count)
                encoder.pump(Array(payload[offset ..< end]), appendingTo: &coded)
                offset = end
            }
            let progress = encoder.pump([], appendingTo: &coded, flush: .finish)
            #expect(progress == .finished)
            if let reference {
                #expect(coded == reference, "chunking \(chunking) diverged")
            }
            else {
                reference = coded
            }
        }
    }

    @Test("raw streams are byte-identical across chunk sizes")
    func rawChunkStability() {
        let payload = DeflateCorpus.text(120_000)
        var reference: [UInt8]?
        for chunking in chunkings {
            var deflator = Deflator()
            var coded: [UInt8] = []
            var offset = 0
            while offset < payload.count {
                let step = chunking == Int.max ? payload.count : chunking
                let end = min(offset + step, payload.count)
                _ = deflator.pump(Array(payload[offset ..< end]), appendingTo: &coded)
                offset = end
            }
            _ = deflator.pump([], appendingTo: &coded, flush: .finish)
            if let reference {
                #expect(coded == reference, "chunking \(chunking) diverged")
            }
            else {
                reference = coded
            }
        }
    }

    @Test("the one-shot and the streamed gzip coding are byte-identical (the middleware contract)")
    func oneShotEqualsStreamed() {
        let payload = DeflateCorpus.text(80_000)
        let oneShot = DeflateCodec.gzip(payload)
        var encoder = GzipDeflator()
        var streamed: [UInt8] = []
        var offset = 0
        while offset < payload.count {
            let end = min(offset + 1_000, payload.count)
            encoder.pump(Array(payload[offset ..< end]), appendingTo: &streamed)
            offset = end
        }
        encoder.pump([], appendingTo: &streamed, flush: .finish)
        #expect(oneShot == streamed)
    }

    @Test("inflate is chunk-transparent: any input chunking yields the same octets")
    func inflateChunkTransparent() throws {
        let payload = DeflateCorpus.text(100_000)
        var deflator = Deflator()
        var coded: [UInt8] = []
        _ = deflator.pump(payload, appendingTo: &coded, flush: .finish)
        for chunking in [1, 13, 4_096] {
            var inflator = Inflator()
            var restored: [UInt8] = []
            var offset = 0
            while offset < coded.count {
                let end = min(offset + chunking, coded.count)
                _ = try inflator.pump(
                    Array(coded[offset ..< end]),
                    appendingTo: &restored,
                    limit: payload.count + 64
                )
                offset = end
            }
            #expect(restored == payload, "chunking \(chunking)")
        }
    }
}
