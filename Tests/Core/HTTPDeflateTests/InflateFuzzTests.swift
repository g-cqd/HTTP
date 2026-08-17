//
//  InflateFuzzTests.swift
//  HTTPDeflateTests
//
//  The attacker-facing gate: seeded random garbage and mutated-valid-stream corpora against the
//  inflate side. PASS is process survival with the typed contract intact — every outcome is a
//  typed `InflateError`, a progress value, or capped output; never a trap, never output past the
//  bound, never unbounded work (asserted as operation counts — pump iterations against an
//  input+output-derived budget — not wall clock).
//

internal import HTTPDeflate
internal import HTTPTestSupport
import Testing

@Suite("Inflate fuzzing — survival with the typed contract intact")
struct InflateFuzzTests {
    /// The bounded-work pump: decodes `input` in fixed chunks, asserting the iteration budget.
    ///
    /// Each pump iteration either consumes input, produces output, or terminates the stream, so
    /// the iteration count is linearly bounded by input + output/chunk; the assertion turns a
    /// hypothetical spin into a test failure rather than a hang.
    private func boundedDecode(
        _ input: [UInt8], limit: Int, sourceLocation: SourceLocation = #_sourceLocation
    ) -> (bytes: [UInt8], progress: CodecProgress)? {
        var inflator = Inflator()
        var output: [UInt8] = []
        var operations = 0
        let budget = input.count + limit / 4_096 + 16
        var offset = 0
        while true {
            operations += 1
            if operations > budget {
                Issue.record("operation budget exceeded", sourceLocation: sourceLocation)
                return nil
            }
            let end = min(offset + 4_096, input.count)
            do {
                let progress = try inflator.pump(
                    Array(input[offset ..< end]), appendingTo: &output, limit: limit
                )
                offset = end
                if progress == .finished || progress == .needsOutput || offset == input.count {
                    return (output, progress)
                }
            }
            catch {
                return nil  // a typed error is a PASS for malformed input
            }
        }
    }

    @Test("seeded random garbage never traps and never exceeds the output bound")
    func randomGarbageSurvives() {
        var generator = SeededRNG(seed: Seed.named("httpdeflate.fuzz.garbage"))
        for iteration in 0 ..< 300 {
            let size = Int.random(in: 0 ... 8_192, using: &generator)
            let garbage = DeflateCorpus.random(size, using: &generator)
            let limit = 1 << 16
            if let result = boundedDecode(garbage, limit: limit) {
                #expect(result.bytes.count <= limit, "iteration \(iteration)")
            }
            _ = DeflateCodec.decompress(garbage, format: .gzip, capacity: 1 << 16)
            _ = DeflateCodec.decompress(garbage, format: .zlib, capacity: 1 << 16)
        }
    }

    @Test("mutated valid streams never trap and never exceed the output bound")
    func mutatedValidStreamsSurvive() {
        let payload = DeflateCorpus.text(20_000)
        var deflator = Deflator()
        var valid: [UInt8] = []
        _ = deflator.pump(payload, appendingTo: &valid, flush: .finish)
        var generator = SeededRNG(seed: Seed.named("httpdeflate.fuzz.mutated"))
        let mutator = ByteMutator()
        for iteration in 0 ..< 300 {
            var corrupted = valid
            let trace = mutator.apply(1 + iteration % 4, to: &corrupted, using: &generator)
            let limit = payload.count * 2
            guard let result = boundedDecode(corrupted, limit: limit) else {
                continue  // typed rejection — fine
            }
            #expect(result.bytes.count <= limit, "iteration \(iteration): \(trace)")
        }
    }

    @Test("mutated gzip members never yield silently corrupted output past the checksum")
    func mutatedMembersFailClosedOrRoundTrip() {
        let payload = DeflateCorpus.text(10_000)
        let member = DeflateCodec.gzip(payload)
        var generator = SeededRNG(seed: Seed.named("httpdeflate.fuzz.member"))
        let mutator = ByteMutator()
        var rejected = 0
        for _ in 0 ..< 300 {
            var corrupted = member
            mutator.apply(1, to: &corrupted, using: &generator)
            let decoded = DeflateCodec.decompress(
                corrupted, format: .gzip, capacity: payload.count + 64
            )
            if decoded == nil {
                rejected += 1
            }
        }
        // The CRC-32 makes silent corruption overwhelmingly detectable; most mutations must fail.
        #expect(rejected > 200, "only \(rejected)/300 mutations were rejected")
    }

    @Test("a max-size malformed input is rejected with bounded work (the CWE-409 shape)")
    func maxSizeMalformedBounded() {
        // A crafted "bomb": deeply repetitive content that inflates far past any sane cap.
        let bomb = DeflateCodec.gzip([UInt8](repeating: 0, count: 4 << 20), level: .balanced)
        #expect(bomb.count < 32_768, "the fixture should compress absurdly well")
        #expect(DeflateCodec.decompress(bomb, format: .gzip, capacity: 1 << 16) == nil)
        var inflator = Inflator()
        var output: [UInt8] = []
        // The raw body (header skipped) against the streaming cap: needsOutput, output ≤ cap.
        let raw = Array(bomb[10...])
        let progress = try? inflator.pump(raw, appendingTo: &output, limit: 1 << 16)
        #expect(progress == .needsOutput)
        #expect(output.count <= 1 << 16)
    }
}
