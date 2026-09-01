//
//  RequestBodyWindowTests.swift
//  HTTPServerTests
//
//  The fixed receive window a streamed HTTP/1.1 chunked body is framed inside (audit CR-F5 / addendum
//  P0.4). The property under test is retention, not correctness of any one read: however many octets
//  pass through it, the window's storage stays inside its capacity — that is what turns an
//  arbitrarily large upload into bounded memory (CWE-400).
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Streamed request-body receive window")
struct RequestBodyWindowTests {
    @Test("frames from a seed and hands the unframed remainder back")
    func seedsAndReportsRemainder() {
        var window = RequestBodyWindow(capacity: 64, seeding: Array("abcdef".utf8)[...])
        #expect(window.unframedCount == 6)
        window.advance(to: 4)
        #expect(window.unframedCount == 2)
        #expect(Array(window.remainder) == Array("ef".utf8))
    }

    @Test("compaction drops the framed prefix and reopens exactly that much room")
    func compactionReopensRoom() {
        var window = RequestBodyWindow(capacity: 16, seeding: Array("0123456789".utf8)[...])
        window.advance(to: 8)
        #expect(window.makeRoom() == 14)  // 16 capacity − the 2 octets still unframed
        #expect(window.bytes.count == 2)
        #expect(window.position == 0)
        #expect(Array(window.remainder) == Array("89".utf8))
    }

    @Test(
        "an arbitrarily large stream never grows the window past its capacity",
        arguments: [
            (capacity: 64, read: 16),
            (capacity: 1_024, read: 1_024),
            (capacity: 100, read: 7)
        ])
    func staysWithinCapacity(_ testCase: (capacity: Int, read: Int)) {
        var window = RequestBodyWindow(capacity: testCase.capacity, seeding: [])
        // The storage is reserved once at init (the allocator rounds it up); it must never be
        // *reallocated* thereafter, which is the retention property stated exactly.
        let reserved = window.bytes.capacity
        var delivered = 0
        // 512 KiB through a window of at most 1 KiB — the shape of a large upload against a small
        // window, driven exactly as the producer drives it: compact, receive into the room reported,
        // frame everything, repeat.
        while delivered < 512 * 1_024 {
            let room = window.makeRoom()
            #expect(room > 0)
            let take = min(room, testCase.read)
            window.append([UInt8](repeating: 0x41, count: take))
            delivered += take
            #expect(window.bytes.count <= testCase.capacity)
            window.advance(to: window.bytes.count)  // the decoder framed everything available
        }
        #expect(window.bytes.capacity == reserved)
    }

    @Test("a seed larger than the capacity is accepted, then compacted back under it")
    func oversizedSeedIsBroughtBackUnderCapacity() {
        // The head read overshoots the header section by up to its own read size, which is bounded
        // independently of this window — so the seed may legitimately arrive larger than the window.
        let seed = [UInt8](repeating: 0x41, count: 32)
        var window = RequestBodyWindow(capacity: 8, seeding: seed[...])
        #expect(window.unframedCount == 32)
        window.advance(to: 32)
        #expect(window.makeRoom() == 8)
        #expect(window.bytes.isEmpty)
    }
}
