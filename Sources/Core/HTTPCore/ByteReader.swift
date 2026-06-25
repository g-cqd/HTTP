//
//  ByteReader.swift
//  HTTPCore
//
//  A zero-copy, bounds-checked forward cursor over a borrowed byte buffer — the foundation of the
//  allocation-free parsers.
//

/// A zero-copy, bounds-checked forward cursor over a borrowed byte buffer.
///
/// `ByteReader` borrows a `RawSpan` and tracks an offset; it **never copies** the underlying bytes.
/// Tokens are returned as `Range<Int>` into the buffer (also copy-free); ``slice(in:)`` hands back a
/// borrowed `RawSpan` sub-view, and bytes become an owned value (e.g. a `String` via ``string(in:)``)
/// only at the single boundary where data must outlive the buffer. Every accessor is bounds-checked,
/// so adversarial input can never trigger an out-of-bounds read; the parsers built on top are
/// iterative (no recursion), so they cannot exhaust the stack.
///
/// Because the backing store is a `RawSpan`, the reader is `~Escapable`: the compiler **statically
/// guarantees** it cannot outlive its buffer — the safety that a raw `UnsafeRawBufferPointer` could
/// previously promise only in a comment. The cursor is still `Copyable`, so a parser can cheaply
/// snapshot a position (copy the reader) and restore it for bounded look-ahead without recursion.
public struct ByteReader: ~Escapable {
    @usableFromInline
    let bytes: RawSpan

    @usableFromInline
    var offset: Int

    /// Creates a reader over `bytes`, starting at `startingAt` (clamped to `0...count`).
    @inlinable
    @_lifetime(copy bytes)
    public init(_ bytes: RawSpan, startingAt: Int = 0) {
        self.bytes = bytes
        self.offset = max(0, min(startingAt, bytes.byteCount))
    }

    /// Creates a reader over a raw buffer, starting at `startingAt` (clamped to `0...count`).
    ///
    /// The reader borrows `buffer`; being `~Escapable`, it cannot outlive that borrow, so the
    /// idiomatic use is inside a `withUnsafeBytes` scope or a Network.framework receive callback.
    @inlinable
    @_lifetime(borrow buffer)
    public init(_ buffer: UnsafeRawBufferPointer, startingAt: Int = 0) {
        self.init(buffer.bytes, startingAt: startingAt)
    }

    /// The total number of bytes in the borrowed buffer.
    @inlinable
    public var count: Int { bytes.byteCount }

    /// The current read position.
    @inlinable
    public var position: Int { offset }

    /// The number of bytes between the current position and the end of the buffer.
    @inlinable
    public var remaining: Int { bytes.byteCount - offset }

    /// Whether the cursor has reached the end of the buffer.
    @inlinable
    public var isAtEnd: Bool { offset >= bytes.byteCount }

    /// Loads the byte at `index`; callers guarantee `0 <= index < count`.
    @usableFromInline
    @inline(__always)
    func loadByte(at index: Int) -> UInt8 {
        bytes.unsafeLoad(fromByteOffset: index, as: UInt8.self)
    }

    /// Returns the byte at the current position without advancing, or `nil` at end of buffer.
    @inlinable
    public func peek() -> UInt8? {
        offset < bytes.byteCount ? loadByte(at: offset) : nil
    }

    /// Returns the byte `distance` bytes ahead of the current position, or `nil` if out of bounds.
    @inlinable
    public func peek(ahead distance: Int) -> UInt8? {
        let index = offset + distance
        guard index >= 0, index < bytes.byteCount else {
            return nil
        }
        return loadByte(at: index)
    }

    /// Reads the byte at the current position and advances by one, or returns `nil` at end.
    @inlinable
    public mutating func readByte() -> UInt8? {
        guard offset < bytes.byteCount else {
            return nil
        }
        defer { offset += 1 }
        return loadByte(at: offset)
    }

    /// Advances the cursor by `distance` bytes.
    ///
    /// Returns `false` if the advance would move outside `0...count`, in which case the cursor is
    /// clamped to the end of the buffer; otherwise advances and returns `true`.
    @inlinable
    @discardableResult
    public mutating func advance(by distance: Int = 1) -> Bool {
        let target = offset + distance
        guard target >= 0, target <= bytes.byteCount else {
            offset = bytes.byteCount
            return false
        }
        offset = target
        return true
    }

    /// Returns the index of the first occurrence of `byte` at or after the current position.
    ///
    /// Returns `nil` if `byte` does not occur. Iterative; never advances the cursor or copies bytes.
    ///
    /// NOTE (measured, Phase 1.1): an 8-byte SWAR zero-byte scan (and a libc `memchr`) were A/B
    /// benchmarked against this scalar loop and are **not** a clear win. HTTP/1.1 request lines and most
    /// header lines are short (≈20–50 B), so the delimiter usually falls inside the first word, where a
    /// SWAR word-load + mask + `trailingZeroBitCount` costs about as much as a few byte compares:
    /// `core/ByteReader/readSlice-to-CRLF` stayed flat, `http1/HeaderParser/parse` improved ≈5% but
    /// `http1/RequestLineParser/parse` regressed ≈2%, and the end-to-end `http1/RequestParser/realistic`
    /// moved < 1% (noise). The scalar scan is the measured optimum for short delimiters; do not
    /// "optimize" it into SWAR/`memchr` (the unaligned-load + endianness cost is not repaid here). Same
    /// lesson as the rejected lookup table in ``FieldValidation/isTokenByte(_:)``.
    @inlinable
    public func firstIndex(of byte: UInt8) -> Int? {
        var index = offset
        while index < bytes.byteCount {
            if loadByte(at: index) == byte {
                return index
            }
            index += 1
        }
        return nil
    }

    /// Reads bytes up to (but not including) the next `delimiter`, advancing the cursor just past the
    /// delimiter, and returns the half-open range of the bytes read (excluding the delimiter).
    ///
    /// Returns `nil` and leaves the cursor unchanged if the delimiter does not occur.
    @inlinable
    public mutating func readSlice(until delimiter: UInt8) -> Range<Int>? {
        guard let end = firstIndex(of: delimiter) else {
            return nil
        }
        let slice = offset ..< end
        offset = end + 1  // advance just past the delimiter
        return slice
    }

    /// Returns the bytes in `range` as a single borrowed `RawSpan`, clamped to the buffer.
    ///
    /// Zero-copy: the span borrows the underlying buffer (and, being `~Escapable`, cannot outlive
    /// it). Use it to validate or compare a parsed token without allocating; call ``string(in:)``
    /// only when an owned value must escape.
    @inlinable
    @_lifetime(copy self)
    public func slice(in range: Range<Int>) -> RawSpan {
        let lower = max(0, min(range.lowerBound, bytes.byteCount))
        let upper = max(lower, min(range.upperBound, bytes.byteCount))
        return bytes.extracting(lower ..< upper)
    }

    /// Decodes the bytes in `range` as UTF-8 into an owned `String`.
    ///
    /// This is the single materialization boundary: parsing stays zero-copy up to here, then copies
    /// exactly once when a value must outlive the borrowed buffer.
    @inlinable
    public func string(in range: Range<Int>) -> String {
        slice(in: range).withUnsafeBytes { String(decoding: $0, as: Unicode.UTF8.self) }
    }
}
