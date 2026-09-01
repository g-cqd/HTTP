//
//  SyncFlushTests.swift
//  HTTPDeflateTests
//
//  RFC 7692 §7.2 semantics on the raw codec: every sync flush ends `00 00 FF FF` on a byte
//  boundary, an empty message flushes to the `00` block header alone (after tail-stripping), the
//  window persists across messages (context takeover — the second identical message compresses
//  smaller and decodes against the first's history), and `reset()` severs that history on both
//  sides.
//

internal import HTTPDeflate
import Testing

@Suite("RFC 7692 §7.2 — sync flush and context takeover")
struct SyncFlushTests {
    @Test("every sync flush ends with the 00 00 FF FF empty stored block")
    func syncTailPresent() {
        var deflator = Deflator()
        for size in [0, 1, 5, 4_096, 100_000] {
            var coded: [UInt8] = []
            let progress = deflator.pump(
                [UInt8](repeating: 0x61, count: size), appendingTo: &coded, flush: .sync
            )
            #expect(progress == .needsInput)
            #expect(coded.suffix(4) == [0x00, 0x00, 0xFF, 0xFF], "size \(size)")
        }
    }

    @Test("an empty message sync-flushes to exactly the aligned empty stored block")
    func emptyMessageShape() {
        var deflator = Deflator()
        var coded: [UInt8] = []
        _ = deflator.pump([], appendingTo: &coded, flush: .sync)
        #expect(coded == [0x00, 0x00, 0x00, 0xFF, 0xFF])
    }

    @Test("context takeover: a repeated message compresses smaller and still decodes in order")
    func contextTakeover() throws {
        let message = Array("the quick brown fox jumps over the lazy dog".utf8)
        var sender = Deflator()
        var receiver = Inflator()
        var first: [UInt8] = []
        _ = sender.pump(message, appendingTo: &first, flush: .sync)
        var second: [UInt8] = []
        _ = sender.pump(message, appendingTo: &second, flush: .sync)
        #expect(second.count < first.count, "the second message should ride the first's window")
        var restored: [UInt8] = []
        _ = try receiver.pump(first, appendingTo: &restored, limit: 1 << 20)
        #expect(restored == message)
        var restoredSecond: [UInt8] = []
        _ = try receiver.pump(second, appendingTo: &restoredSecond, limit: 1 << 20)
        #expect(restoredSecond == message)
    }

    @Test("reset() severs the history on both sides (no_context_takeover)")
    func resetSeversHistory() throws {
        let message = Array("alpha alpha alpha alpha".utf8)
        var sender = Deflator()
        var first: [UInt8] = []
        _ = sender.pump(message, appendingTo: &first, flush: .sync)
        sender.reset()
        var second: [UInt8] = []
        _ = sender.pump(message, appendingTo: &second, flush: .sync)
        #expect(first == second, "reset must make messages independent and identical")
        // A reset receiver decodes each independently, in any order.
        var receiver = Inflator()
        var restored: [UInt8] = []
        _ = try receiver.pump(second, appendingTo: &restored, limit: 1 << 20)
        #expect(restored == message)
        receiver.reset()
        var restoredFirst: [UInt8] = []
        _ = try receiver.pump(first, appendingTo: &restoredFirst, limit: 1 << 20)
        #expect(restoredFirst == message)
    }

    @Test("a receiver that missed the history rejects a context-dependent message, fail closed")
    func missingHistoryFailsClosed() throws {
        let message = Array(
            String(repeating: "context takeover needs the previous window. ", count: 20).utf8
        )
        var sender = Deflator()
        var first: [UInt8] = []
        _ = sender.pump(message, appendingTo: &first, flush: .sync)
        var second: [UInt8] = []
        _ = sender.pump(message, appendingTo: &second, flush: .sync)
        var lateJoiner = Inflator()
        var restored: [UInt8] = []
        // The second message back-references the first's octets, which this receiver never saw:
        // that must surface as a typed distance error, never garbage output.
        #expect(throws: InflateError.distanceTooFar) {
            _ = try lateJoiner.pump(second, appendingTo: &restored, limit: 1 << 20)
        }
    }

    @Test("multiple sync-flushed segments concatenate into one decodable stream")
    func segmentsConcatenate() throws {
        var sender = Deflator()
        var stream: [UInt8] = []
        var whole: [UInt8] = []
        for index in 0 ..< 10 {
            let segment = DeflateCorpus.text(500 + index * 37)
            whole.append(contentsOf: segment)
            _ = sender.pump(segment, appendingTo: &stream, flush: .sync)
        }
        var receiver = Inflator()
        var restored: [UInt8] = []
        let progress = try receiver.pump(stream, appendingTo: &restored, limit: whole.count + 64)
        #expect(progress == .needsInput)
        #expect(restored == whole)
    }
}
