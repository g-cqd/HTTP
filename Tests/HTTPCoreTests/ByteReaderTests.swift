//
//  ByteReaderTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the zero-copy ByteReader cursor.
//

import Testing

@testable import HTTPCore

@Suite("ByteReader — zero-copy cursor")
struct ByteReaderTests {
    /// Runs `body` with a `ByteReader` that borrows the UTF-8 bytes of `string`.
    private func withReader(over string: String, _ body: (inout ByteReader) -> Void) {
        let bytes = Array(string.utf8)
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            body(&reader)
        }
    }

    @Test("peek does not advance; readByte advances and stops at end")
    func peekAndRead() {
        withReader(over: "AB") { reader in
            #expect(reader.peek() == UInt8(ascii: "A"))
            #expect(reader.position == 0)
            let first = reader.readByte()
            let second = reader.readByte()
            let past = reader.readByte()
            #expect(first == UInt8(ascii: "A"))
            #expect(second == UInt8(ascii: "B"))
            #expect(past == nil)
            // `~Escapable` `ByteReader` can't use the `#expect(reader.prop)` property-access form
            // (it requires `Escapable`); bind the Bool first.
            let atEnd = reader.isAtEnd
            #expect(atEnd)
        }
    }

    @Test("peek(ahead:) is bounds-checked in both directions")
    func peekAhead() {
        withReader(over: "AB") { reader in
            #expect(reader.peek(ahead: 1) == UInt8(ascii: "B"))
            #expect(reader.peek(ahead: 2) == nil)
            #expect(reader.peek(ahead: -1) == nil)
        }
    }

    @Test("advance clamps at the end and reports overflow")
    func advanceClamps() {
        withReader(over: "ABC") { reader in
            let ok = reader.advance(by: 2)
            let overflow = reader.advance(by: 5)
            #expect(ok)
            #expect(!overflow)
            let atEnd = reader.isAtEnd
            #expect(atEnd)
            #expect(reader.position == 3)
        }
    }

    @Test("firstIndex(of:) finds a byte at/after the cursor without copying")
    func firstIndexOf() {
        withReader(over: "key: value") { reader in
            #expect(reader.firstIndex(of: UInt8(ascii: ":")) == 3)
            let missingByteIndex = reader.firstIndex(of: UInt8(ascii: "?"))
            #expect(missingByteIndex == nil)
            #expect(reader.position == 0)  // non-mutating
        }
    }

    @Test("readSlice(until:) returns the range before the delimiter and skips past it")
    func readSliceUntilDelimiter() {
        withReader(over: "GET /path\r\n") { reader in
            let method = reader.readSlice(until: UInt8(ascii: " "))
            #expect(method == 0 ..< 3)  // "GET"
            #expect(reader.position == 4)  // past the space
            let target = reader.readSlice(until: UInt8(ascii: "\r"))
            #expect(target == 4 ..< 9)  // "/path"
        }
    }

    @Test("readSlice(until:) returns nil and does not advance when the delimiter is absent")
    func readSliceMissingDelimiter() {
        withReader(over: "no-delimiter") { reader in
            let result = reader.readSlice(until: UInt8(ascii: ";"))
            #expect(result == nil)
            #expect(reader.position == 0)
        }
    }

    @Test("string(in:) materializes an owned String once, without moving the cursor")
    func stringMaterializesRange() {
        withReader(over: "GET /path") { reader in
            #expect(reader.string(in: 0 ..< 3) == "GET")
            #expect(reader.string(in: 4 ..< 9) == "/path")
            #expect(reader.position == 0)  // materialization is non-mutating
        }
    }

    @Test("slice(in:) returns a borrowed, copy-free RawSpan over the range")
    func sliceReturnsBorrowedSpan() {
        withReader(over: "GET /path") { reader in
            let span = reader.slice(in: 0 ..< 3)  // "GET"
            #expect(span.byteCount == 3)
            #expect(span.unsafeLoad(fromByteOffset: 0, as: UInt8.self) == UInt8(ascii: "G"))
            #expect(span.unsafeLoad(fromByteOffset: 2, as: UInt8.self) == UInt8(ascii: "T"))
        }
    }

    @Test("slice(in:) clamps an out-of-range request instead of trapping")
    func sliceClampsOutOfRange() {
        withReader(over: "AB") { reader in
            #expect(reader.slice(in: 0 ..< 99).byteCount == 2)
            #expect(reader.slice(in: -5 ..< 1).byteCount == 1)
            #expect(reader.slice(in: 5 ..< 9).byteCount == 0)
        }
    }
}
