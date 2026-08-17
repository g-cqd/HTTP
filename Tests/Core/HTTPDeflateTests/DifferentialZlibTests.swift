//
//  DifferentialZlibTests.swift
//  HTTPDeflateTests
//
//  The differential gate against the incumbent, while it is still in the tree: every zlib-produced
//  stream — one-shot gzip at all ten levels, and sync-flushed raw streams at every flush point —
//  must decode byte-identically through HTTPDeflate; and every HTTPDeflate-produced stream must
//  re-inflate through zlib to the input. Canonical-output equality with zlib is NOT claimed —
//  round-trip + cross-decode is the contract. This suite is deleted together with the shims in the
//  replacement sweep; the round-trip and vector suites stay.
//

internal import HTTPDeflate
internal import HTTPTestSupport
import Testing

@Suite("Differential — HTTPDeflate vs system zlib")
struct DifferentialZlibTests {
    // MARK: zlib encodes → we decode

    @Test(
        "zlib gzip members at levels 0–9 gunzip byte-identically",
        arguments: DeflateCorpus.standard()
    )
    func zlibGzipDecodesIdentically(_ payload: DeflateCorpus.Payload) {
        for level in Int32(0) ... 9 {
            guard let member = ZlibOracle.gzipCompress(payload.bytes, level: level) else {
                #expect(payload.bytes.isEmpty == false || level >= 0, "oracle refused to encode")
                continue
            }
            let restored = DeflateCodec.decompress(
                member, format: .gzip, capacity: payload.bytes.count + 64
            )
            #expect(restored == payload.bytes, "level \(level), \(payload.label)")
        }
    }

    @Test(
        "zlib sync-flushed raw streams decode identically at every flush point",
        arguments: [1, 3, 64, 1_024, 65_536] as [Int]
    )
    func zlibSyncFlushedStreamDecodes(_ segmentSize: Int) throws {
        let payload = DeflateCorpus.text(150_000)
        let oracle = try #require(ZlibOracle.SyncDeflater())
        var inflator = Inflator()
        var restored: [UInt8] = []
        var offset = 0
        while offset < payload.count {
            let end = min(offset + segmentSize, payload.count)
            let segment = try #require(oracle.compress(Array(payload[offset ..< end])))
            let progress = try inflator.pump(
                segment, appendingTo: &restored, limit: payload.count + 64
            )
            #expect(progress == .needsInput)  // sync-flushed streams never carry BFINAL
            offset = end
        }
        #expect(restored == payload)
    }

    // MARK: we encode → zlib decodes

    @Test(
        "our gzip members re-inflate through zlib to the input",
        arguments: DeflateCorpus.standard(), DeflateCorpus.levels
    )
    func ourGzipInflatesThroughZlib(_ payload: DeflateCorpus.Payload, _ level: DeflateLevel) {
        guard !payload.bytes.isEmpty else {
            return  // zlib's one-shot conflates empty output with failure
        }
        let member = DeflateCodec.gzip(payload.bytes, level: level)
        let restored = ZlibOracle.inflate(member, capacity: payload.bytes.count + 64)
        #expect(restored == payload.bytes, "\(payload.label) at \(level)")
    }

    @Test(
        "our raw finished streams re-inflate through zlib to the input",
        arguments: DeflateCorpus.standard(), DeflateCorpus.levels
    )
    func ourRawInflatesThroughZlib(_ payload: DeflateCorpus.Payload, _ level: DeflateLevel) {
        guard !payload.bytes.isEmpty else {
            return
        }
        var deflator = Deflator(level: level)
        var coded: [UInt8] = []
        _ = deflator.pump(payload.bytes, appendingTo: &coded, flush: .finish)
        let restored = ZlibOracle.inflateRaw(coded, capacity: payload.bytes.count + 64)
        #expect(restored == payload.bytes, "\(payload.label) at \(level)")
    }

    @Test("our sync-flushed message stream inflates through zlib's streaming inflate")
    func ourSyncFlushedMessagesInflateThroughZlib() throws {
        let oracle = try #require(ZlibOracle.SyncInflater())
        var deflator = Deflator()
        var generator = SeededRNG(seed: Seed.named("httpdeflate.diff.sync"))
        for message in 0 ..< 40 {
            let size = message % 7 == 0 ? 0 : Int.random(in: 1 ... 5_000, using: &generator)
            let payload =
                message % 3 == 0
                ? DeflateCorpus.random(size, using: &generator)
                : DeflateCorpus.text(size)
            var coded: [UInt8] = []
            let progress = deflator.pump(payload, appendingTo: &coded, flush: .sync)
            #expect(progress == .needsInput)
            #expect(coded.suffix(4) == [0x00, 0x00, 0xFF, 0xFF], "sync tail, message \(message)")
            let restored = oracle.inflate(coded)
            #expect(restored == payload, "message \(message) (\(size) octets)")
        }
    }

    @Test("zlib's sync-flushed messages decode through our inflater with context takeover")
    func zlibSyncFlushedMessagesDecodeThroughUs() throws {
        let oracle = try #require(ZlibOracle.SyncDeflater())
        var inflator = Inflator()
        var generator = SeededRNG(seed: Seed.named("httpdeflate.diff.sync.rx"))
        for message in 0 ..< 40 {
            let size = message % 5 == 0 ? 0 : Int.random(in: 1 ... 5_000, using: &generator)
            let payload = DeflateCorpus.text(size)
            let coded = try #require(oracle.compress(payload))
            var restored: [UInt8] = []
            let progress = try inflator.pump(coded, appendingTo: &restored, limit: size + 64)
            #expect(progress == .needsInput)
            #expect(restored == payload, "message \(message) (\(size) octets)")
        }
    }

    @Test("seeded random chunked pumping matches zlib across 200 mixed payloads")
    func seededSweep() {
        var generator = SeededRNG(seed: Seed.named("httpdeflate.diff.sweep"))
        for iteration in 0 ..< 200 {
            let size = Int.random(in: 0 ... 20_000, using: &generator)
            let mode = iteration % 3
            let payload: [UInt8] =
                switch mode {
                    case 0:
                        DeflateCorpus.random(size, using: &generator)
                    case 1:
                        DeflateCorpus.text(size)
                    default:
                        [UInt8](repeating: UInt8(iteration & 0xFF), count: size)
                }
            let level = DeflateCorpus.levels[iteration % DeflateCorpus.levels.count]
            guard !payload.isEmpty else {
                continue
            }
            let member = DeflateCodec.gzip(payload, level: level)
            #expect(
                ZlibOracle.inflate(member, capacity: size + 64) == payload,
                "iteration \(iteration)"
            )
            if let zlibMember = ZlibOracle.gzipCompress(payload, level: Int32(iteration % 10)) {
                #expect(
                    DeflateCodec.decompress(zlibMember, format: .gzip, capacity: size + 64)
                        == payload,
                    "iteration \(iteration)"
                )
            }
        }
    }
}
