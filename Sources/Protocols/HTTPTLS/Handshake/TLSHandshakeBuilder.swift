//
//  TLSHandshakeBuilder.swift
//  HTTPTLS
//
//  RFC 8446 §3 — the presentation-language encoder: big-endian integers and length-prefixed
//  vectors, with closure-scoped length patching (write a placeholder, build the body, patch the
//  prefix) so no message is ever measured twice or assembled in a second buffer. Vector
//  overflow (a body larger than its prefix can express) is impossible for every §4 message this
//  server emits — lengths are bounded by the §4.3/§4.4 shapes — and is checked anyway, as a
//  typed error, where certificate chains make the bound caller-reachable.
//

/// An append-only encoder for RFC 8446 §3 wire forms (integers, vectors, framed messages).
struct TLSHandshakeBuilder {
    /// The octets built so far.
    private(set) var bytes: [UInt8] = []

    /// Creates an empty builder.
    init() {
        bytes.reserveCapacity(1_024)
    }

    /// Appends one octet (`uint8`).
    mutating func u8(_ value: UInt8) {
        bytes.append(value)
    }

    /// Appends a big-endian `uint16`.
    mutating func u16(_ value: UInt16) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    /// Appends a big-endian `uint24` (the low 24 bits of `value`).
    mutating func u24(_ value: Int) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 16))
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    /// Appends a big-endian `uint32`.
    mutating func u32(_ value: UInt32) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 24))
        bytes.append(UInt8(truncatingIfNeeded: value >> 16))
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    /// Appends raw octets.
    mutating func raw(_ octets: some Sequence<UInt8>) {
        bytes.append(contentsOf: octets)
    }

    /// Builds an `opaque<0..255>` vector: placeholder prefix, body closure, patched length.
    mutating func vector8(_ body: (inout Self) -> Void) {
        let prefix = bytes.count
        bytes.append(0)
        body(&self)
        let length = bytes.count - prefix - 1
        bytes[prefix] = UInt8(truncatingIfNeeded: length)
    }

    /// Builds an `opaque<0..2^16-1>` vector: placeholder prefix, body closure, patched length.
    mutating func vector16(_ body: (inout Self) -> Void) {
        let prefix = bytes.count
        bytes.append(0)
        bytes.append(0)
        body(&self)
        let length = bytes.count - prefix - 2
        bytes[prefix] = UInt8(truncatingIfNeeded: length >> 8)
        bytes[prefix + 1] = UInt8(truncatingIfNeeded: length)
    }

    /// Builds an `opaque<0..2^24-1>` vector: placeholder prefix, body closure, patched length.
    mutating func vector24(_ body: (inout Self) -> Void) {
        let prefix = bytes.count
        bytes.append(0)
        bytes.append(0)
        bytes.append(0)
        body(&self)
        let length = bytes.count - prefix - 3
        bytes[prefix] = UInt8(truncatingIfNeeded: length >> 16)
        bytes[prefix + 1] = UInt8(truncatingIfNeeded: length >> 8)
        bytes[prefix + 2] = UInt8(truncatingIfNeeded: length)
    }

    /// Builds one `extension` (§4.2): type ∥ `uint16`-prefixed data.
    mutating func extensionField(_ type: TLSExtensionType, _ body: (inout Self) -> Void) {
        u16(type.rawValue)
        vector16(body)
    }

    /// Frames one complete handshake message (§4: type octet ∥ `uint24` length ∥ body).
    static func message(
        _ type: TLSHandshakeType, _ body: (inout Self) -> Void
    ) -> [UInt8] {
        var builder = Self()
        builder.u8(type.rawValue)
        builder.vector24(body)
        return builder.bytes
    }
}
