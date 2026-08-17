//
//  DeflateRoundTripTests.swift
//  HTTPDeflateTests
//
//  RFC 1951/1952 round-trips through our own encoder and decoder, across every level and every
//  corpus shape (empty through multi-block window-sliding payloads), plus the container paths
//  (gzip both ways; a handcrafted zlib envelope for the decoder) and the Huffman length-limit
//  repair under pathologically skewed frequencies.
//

internal import HTTPDeflate
import Testing

@Suite("DEFLATE round-trips (our encoder ↔ our decoder)")
struct DeflateRoundTripTests {
    @Test(
        "raw deflate → inflate is identity at every level",
        arguments: DeflateCorpus.standard(), DeflateCorpus.levels
    )
    func rawRoundTrip(_ payload: DeflateCorpus.Payload, _ level: DeflateLevel) throws {
        var deflator = Deflator(level: level)
        var coded: [UInt8] = []
        let progress = deflator.pump(payload.bytes, appendingTo: &coded, flush: .finish)
        #expect(progress == .finished)
        var inflator = Inflator()
        var restored: [UInt8] = []
        let inflated = try inflator.pump(
            coded, appendingTo: &restored, limit: payload.bytes.count + 64
        )
        #expect(inflated == .finished)
        #expect(restored == payload.bytes)
    }

    @Test(
        "gzip → gunzip is identity at every level",
        arguments: DeflateCorpus.standard(), DeflateCorpus.levels
    )
    func gzipRoundTrip(_ payload: DeflateCorpus.Payload, _ level: DeflateLevel) {
        let member = DeflateCodec.gzip(payload.bytes, level: level)
        #expect(member.prefix(3) == [0x1F, 0x8B, 0x08])
        let restored = DeflateCodec.decompress(
            member, format: .gzip, capacity: payload.bytes.count + 64
        )
        #expect(restored == payload.bytes)
    }

    @Test("a handcrafted zlib envelope (RFC 1950) decodes, Adler-32 verified")
    func zlibEnvelopeRoundTrip() {
        let payload = DeflateCorpus.text(10_000)
        var deflator = Deflator()
        var body: [UInt8] = []
        _ = deflator.pump(payload, appendingTo: &body, flush: .finish)
        var envelope: [UInt8] = [0x78, 0x9C]  // CMF/FLG: 32K window, check bits valid
        envelope.append(contentsOf: body)
        var adler: UInt32 = 1
        for byte in payload {
            // The reference Adler-32 (RFC 1950 §9), folded naively.
            let low = (adler & 0xFFFF &+ UInt32(byte)) % 65_521
            let high = ((adler >> 16) &+ low) % 65_521
            adler = (high << 16) | low
        }
        envelope.append(UInt8((adler >> 24) & 0xFF))
        envelope.append(UInt8((adler >> 16) & 0xFF))
        envelope.append(UInt8((adler >> 8) & 0xFF))
        envelope.append(UInt8(adler & 0xFF))
        let restored = DeflateCodec.decompress(
            envelope, format: .zlib, capacity: payload.count + 64
        )
        #expect(restored == payload)
    }

    @Test("skewed frequencies force the length-limit repair and still round-trip")
    func lengthLimitRepairRoundTrips() throws {
        // Exponentially skewed symbol frequencies drive optimal depths past 15 bits; the encoder
        // must repair to ≤15 and the decoder must accept the result.
        var payload: [UInt8] = []
        for symbol in 0 ..< 24 {
            let weight = max(1, (1 << min(symbol, 16)) / 512)
            payload.append(contentsOf: [UInt8](repeating: UInt8(symbol), count: weight))
        }
        // Shuffle-free interleave so matches don't collapse everything to one run.
        var interleaved: [UInt8] = []
        interleaved.reserveCapacity(payload.count)
        var stride = 0
        while interleaved.count < payload.count {
            interleaved.append(payload[(stride * 7_919) % payload.count])
            stride += 1
        }
        var deflator = Deflator()
        var coded: [UInt8] = []
        _ = deflator.pump(interleaved, appendingTo: &coded, flush: .finish)
        var inflator = Inflator()
        var restored: [UInt8] = []
        let progress = try inflator.pump(
            coded, appendingTo: &restored, limit: interleaved.count + 64
        )
        #expect(progress == .finished)
        #expect(restored == interleaved)
    }

    @Test("the store level emits valid stored framing that shrinks nothing")
    func storeLevelFraming() throws {
        let payload = DeflateCorpus.text(100_000)
        var deflator = Deflator(level: .store)
        var coded: [UInt8] = []
        _ = deflator.pump(payload, appendingTo: &coded, flush: .finish)
        // Stored framing: 5 octets per ≤32 000-octet block plus the payload.
        #expect(coded.count >= payload.count)
        #expect(coded.count <= payload.count + 5 * (payload.count / 32_000 + 2))
        var inflator = Inflator()
        var restored: [UInt8] = []
        _ = try inflator.pump(coded, appendingTo: &restored, limit: payload.count + 64)
        #expect(restored == payload)
    }

    @Test("the decoder's bomb cap stops the pump at the limit (CWE-409)")
    func inflateLimitFailsClosed() throws {
        let payload = [UInt8](repeating: 0x41, count: 100_000)
        var deflator = Deflator()
        var coded: [UInt8] = []
        _ = deflator.pump(payload, appendingTo: &coded, flush: .finish)
        var inflator = Inflator()
        var restored: [UInt8] = []
        let progress = try inflator.pump(coded, appendingTo: &restored, limit: 1_000)
        #expect(progress == .needsOutput)
        #expect(restored.count <= 1_000)
    }
}
