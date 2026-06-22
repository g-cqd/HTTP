//
//  QPACKStaticTableTests.swift
//  QPACKTests
//
//  RED→GREEN driver for the RFC 9204 Appendix A static table: the 99-entry count, the 0-based
//  addressing (the trap that separates it from HPACK's 1-based/61-entry table), boundary entries, and
//  out-of-range indexing.
//

import HTTPCore
import Testing

@testable import QPACK

@Suite("RFC 9204 Appendix A — QPACK static table")
struct QPACKStaticTableTests {

    @Test("the static table has exactly 99 entries")
    func count() {
        #expect(QPACKStaticTable.count == 99)
        #expect(QPACKStaticTable.entries.count == 99)
    }

    @Test(
        "entries are addressed 0-based with the RFC 9204 Appendix A values",
        arguments: [
            (index: 0, expected: HeaderField(name: ":authority")),
            (index: 1, expected: HeaderField(name: ":path", value: "/")),
            (index: 17, expected: HeaderField(name: ":method", value: "GET")),
            (index: 25, expected: HeaderField(name: ":status", value: "200")),
            // index 52 is the no-space form — a transcription trap worth pinning.
            (
                index: 52,
                expected: HeaderField(name: "content-type", value: "text/html;charset=utf-8")
            ),
            (
                index: 73,
                expected: HeaderField(name: "access-control-allow-credentials", value: "FALSE")
            ),
            (index: 98, expected: HeaderField(name: "x-frame-options", value: "sameorigin")),
        ] as [(index: Int, expected: HeaderField)])
    func indexedEntries(_ testCase: (index: Int, expected: HeaderField)) {
        #expect(QPACKStaticTable.field(at: testCase.index) == testCase.expected)
    }

    @Test("out-of-range indices return nil (0...98 only)")
    func outOfRange() {
        #expect(QPACKStaticTable.field(at: -1) == nil)
        #expect(QPACKStaticTable.field(at: 99) == nil)
        #expect(QPACKStaticTable.field(at: Int.max) == nil)
    }

    @Test("encoder lookups resolve exact and name-only static matches")
    func encoderLookups() {
        #expect(QPACKStaticTable.exactIndex[HeaderField(name: ":method", value: "GET")] == 17)
        #expect(QPACKStaticTable.exactIndex[HeaderField(name: ":path", value: "/")] == 1)
        // The lowest index wins for a name with several values (e.g. :status first appears at 24).
        #expect(QPACKStaticTable.nameIndex[":status"] == 24)
        #expect(QPACKStaticTable.nameIndex["content-type"] == 44)
        #expect(QPACKStaticTable.nameIndex["x-frame-options"] == 97)
    }
}
