//
//  ByteReader.swift
//  HTTPCore
//
//  A zero-copy, bounds-checked forward cursor over a borrowed byte buffer — the foundation of the
//  allocation-free parsers.
//

/// A zero-copy, bounds-checked forward cursor over a borrowed byte buffer.
///
/// `ByteReader` borrows an `UnsafeRawBufferPointer` and tracks an offset; it **never copies** the
/// underlying bytes. Tokens are returned as `Range<Int>` into the buffer (also copy-free) and are
/// materialized into owned values (e.g. `String`) only at the boundary where data must outlive the
/// buffer. Every accessor is bounds-checked, so adversarial input can never trigger an out-of-bounds
/// read; the parsers built on top are iterative (no recursion), so they cannot exhaust the stack.
///
/// - Important: the cursor borrows its buffer — the caller must guarantee the buffer outlives the
///   reader (e.g. by using it inside a `withUnsafeBytes` scope or a Network.framework receive
///   callback). Because the cursor is `Copyable`, a parser can cheaply snapshot a position (copy the
///   reader) and restore it for bounded look-ahead without recursion.
public struct ByteReader {

    @usableFromInline
    let bytes: UnsafeRawBufferPointer

    @usableFromInline
    var offset: Int

    /// Creates a reader over `bytes`, starting at `startingAt` (clamped to `0...count`).
    @inlinable
    public init(_ bytes: UnsafeRawBufferPointer, startingAt: Int = 0) {
        self.bytes = bytes
        self.offset = max(0, min(startingAt, bytes.count))
    }

    /// The total number of bytes in the borrowed buffer.
    @inlinable
    public var count: Int { bytes.count }

    /// The current read position.
    @inlinable
    public var position: Int { offset }

    /// The number of bytes between the current position and the end of the buffer.
    @inlinable
    public var remaining: Int { bytes.count - offset }

    /// Whether the cursor has reached the end of the buffer.
    @inlinable
    public var isAtEnd: Bool { offset >= bytes.count }

    /// Returns the byte at the current position without advancing, or `nil` at end of buffer.
    @inlinable
    public func peek() -> UInt8? {
        offset < bytes.count ? bytes[offset] : nil
    }

    /// Returns the byte `distance` bytes ahead of the current position, or `nil` if out of bounds.
    @inlinable
    public func peek(ahead distance: Int) -> UInt8? {
        let index = offset + distance
        guard index >= 0, index < bytes.count else { return nil }
        return bytes[index]
    }

    /// Reads the byte at the current position and advances by one, or returns `nil` at end.
    @inlinable
    public mutating func readByte() -> UInt8? {
        guard offset < bytes.count else { return nil }
        defer { offset += 1 }
        return bytes[offset]
    }

    /// Advances the cursor by `distance` bytes.
    ///
    /// Returns `false` if the advance would move outside `0...count`, in which case the cursor is
    /// clamped to the end of the buffer; otherwise advances and returns `true`.
    @inlinable
    @discardableResult
    public mutating func advance(by distance: Int = 1) -> Bool {
        let target = offset + distance
        guard target >= 0, target <= bytes.count else {
            offset = bytes.count
            return false
        }
        offset = target
        return true
    }

    /// Returns the index of the first occurrence of `byte` at or after the current position.
    ///
    /// Returns `nil` if `byte` does not occur. Iterative; never advances the cursor or copies bytes.
    @inlinable
    public func firstIndex(of byte: UInt8) -> Int? {
        var index = offset
        while index < bytes.count {
            if bytes[index] == byte { return index }
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
        guard let end = firstIndex(of: delimiter) else { return nil }
        let slice = offset..<end
        offset = end + 1  // advance just past the delimiter
        return slice
    }

    /// Returns the bytes in `range` as a single contiguous view, clamped to the buffer.
    ///
    /// Zero-copy: the view borrows the underlying buffer. Use it to validate or compare a parsed
    /// token without allocating; call ``string(in:)`` only when an owned value must escape.
    @inlinable
    public func slice(in range: Range<Int>) -> UnsafeRawBufferPointer {
        let lower = max(0, min(range.lowerBound, bytes.count))
        let upper = max(lower, min(range.upperBound, bytes.count))
        return UnsafeRawBufferPointer(rebasing: bytes[lower..<upper])
    }

    /// Decodes the bytes in `range` as UTF-8 into an owned `String`.
    ///
    /// This is the single materialization boundary: parsing stays zero-copy up to here, then copies
    /// exactly once when a value must outlive the borrowed buffer.
    @inlinable
    public func string(in range: Range<Int>) -> String {
        String(decoding: slice(in: range), as: UTF8.self)
    }
}
