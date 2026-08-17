//
//  TLSHandshakeReader.swift
//  HTTPTLS
//
//  RFC 8446 §3 — the presentation-language decoder: big-endian fixed-width integers and the
//  `opaque foo<a..b>` length-prefixed vectors every §4 message is built from. A cursor over a
//  borrowed slice; nothing is copied. Every underrun or bound violation is a typed
//  ``TLSHandshakeError/malformed(_:)`` (§6.2 `decode_error`), never a trap — the fuzz gate
//  drives arbitrary octets through here.
//

/// A bounds-checked cursor over one handshake message body (RFC 8446 §3's wire forms).
struct TLSHandshakeReader {
    /// The message octets being decoded (a borrowed slice — never copied).
    let bytes: ArraySlice<UInt8>
    /// The read position (advances monotonically; never beyond `bytes.endIndex`).
    private(set) var index: Int

    /// Creates a reader over one message body.
    init(_ bytes: ArraySlice<UInt8>) {
        self.bytes = bytes
        index = bytes.startIndex
    }

    /// How many octets remain unread.
    var remaining: Int {
        bytes.endIndex - index
    }

    /// Whether every octet has been consumed.
    var isAtEnd: Bool {
        index == bytes.endIndex
    }

    /// Fails with §6.2 `decode_error` semantics unless the reader consumed exactly everything —
    /// trailing octets are "a message whose length does not match" (§6.2).
    func expectEnd(of label: String) throws(TLSHandshakeError) {
        guard isAtEnd else {
            throw .malformed("\(label): \(remaining) trailing octet(s)")
        }
    }

    /// Reads one octet (`uint8`).
    mutating func byte(_ label: String) throws(TLSHandshakeError) -> UInt8 {
        guard remaining >= 1 else {
            throw .malformed(label)
        }
        defer { index += 1 }
        return bytes[index]
    }

    /// Reads a big-endian `uint16`.
    mutating func u16(_ label: String) throws(TLSHandshakeError) -> UInt16 {
        guard remaining >= 2 else {
            throw .malformed(label)
        }
        defer { index += 2 }
        return UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
    }

    /// Reads a big-endian `uint24` (§3's three-octet length form) as `Int`.
    mutating func u24(_ label: String) throws(TLSHandshakeError) -> Int {
        guard remaining >= 3 else {
            throw .malformed(label)
        }
        defer { index += 3 }
        return Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
    }

    /// Reads a big-endian `uint32`.
    mutating func u32(_ label: String) throws(TLSHandshakeError) -> UInt32 {
        guard remaining >= 4 else {
            throw .malformed(label)
        }
        defer { index += 4 }
        return UInt32(bytes[index]) << 24 | UInt32(bytes[index + 1]) << 16
            | UInt32(bytes[index + 2]) << 8 | UInt32(bytes[index + 3])
    }

    /// Reads `count` raw octets as a borrowed slice.
    mutating func slice(
        _ count: Int, _ label: String
    ) throws(TLSHandshakeError)
        -> ArraySlice<UInt8>
    {
        guard count >= 0, remaining >= count else {
            throw .malformed(label)
        }
        defer { index += count }
        return bytes[index ..< index + count]
    }

    /// Reads an `opaque foo<0..255>` vector (one-octet length prefix, §3).
    mutating func vector8(_ label: String) throws(TLSHandshakeError) -> ArraySlice<UInt8> {
        let count = try byte(label)
        return try slice(Int(count), label)
    }

    /// Reads an `opaque foo<0..2^16-1>` vector (two-octet length prefix, §3).
    mutating func vector16(_ label: String) throws(TLSHandshakeError) -> ArraySlice<UInt8> {
        let count = try u16(label)
        return try slice(Int(count), label)
    }

    /// Reads an `opaque foo<0..2^24-1>` vector (three-octet length prefix, §3).
    mutating func vector24(_ label: String) throws(TLSHandshakeError) -> ArraySlice<UInt8> {
        let count = try u24(label)
        return try slice(count, label)
    }

    /// Reads a vector of `uint16` values (the §4.2.7/§4.2.3 list shape), enforcing an even
    /// payload length.
    mutating func u16List(_ label: String) throws(TLSHandshakeError) -> [UInt16] {
        let body = try vector16(label)
        guard body.count.isMultiple(of: 2) else {
            throw .malformed("\(label): odd length")
        }
        var values: [UInt16] = []
        values.reserveCapacity(body.count / 2)
        var cursor = body.startIndex
        while cursor < body.endIndex {
            values.append(UInt16(body[cursor]) << 8 | UInt16(body[cursor + 1]))
            cursor += 2
        }
        return values
    }
}
