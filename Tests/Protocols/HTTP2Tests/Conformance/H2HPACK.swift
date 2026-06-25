//
//  H2HPACK.swift
//  HTTP2Tests
//
//  h2spec conformance — the `generic` group, §5 HPACK: the engine MUST accept a request whose header
//  block uses each RFC 7541 §6 field representation. Each case hand-encodes one representation (indexed,
//  literal ± incremental indexing, literal without indexing, literal never indexed, dynamic table size
//  update — raw and Huffman) into a complete, valid request and asserts it decodes to a `.request`.
//  The raw blocks are built on the public canonical `Huffman` codec (HTTPCore) so the ±Huffman variants
//  are exercised deterministically rather than left to the encoder's shorter-of-the-two choice.
//

import HTTPCore

/// Minimal raw HPACK representation encoders (RFC 7541 §6) for the generic HPACK acceptance checks.
///
/// Indices stay < 15 and string lengths < 128, so every prefix integer fits in its first octet — no
/// continuation bytes are needed, keeping the hand-encoding auditable.
enum H2HPACK {
    /// RFC 7541 §5.2 — a string literal, raw (`H`=0) or Huffman-coded (`H`=1).
    static func string(_ value: String, huffman: Bool) -> [UInt8] {
        let bytes = Array(value.utf8)
        if huffman {
            let encoded = Huffman.encode(bytes)
            return [0x80 | UInt8(encoded.count)] + encoded
        }
        return [UInt8(bytes.count)] + bytes
    }

    /// §6.1 — an indexed header field.
    static func indexed(_ index: Int) -> [UInt8] { [0x80 | UInt8(index)] }

    /// §6.2.1 — literal with incremental indexing: indexed name (index>0) or new name (index 0).
    static func incremental(name index: Int, value: String, huffman: Bool) -> [UInt8] {
        [0x40 | UInt8(index)] + string(value, huffman: huffman)
    }
    static func incremental(newName name: String, value: String, huffman: Bool) -> [UInt8] {
        [0x40] + string(name, huffman: huffman) + string(value, huffman: huffman)
    }

    /// §6.2.2 — literal without indexing: indexed name or new name.
    static func withoutIndexing(name index: Int, value: String, huffman: Bool) -> [UInt8] {
        [UInt8(index)] + string(value, huffman: huffman)
    }
    static func withoutIndexing(newName name: String, value: String, huffman: Bool) -> [UInt8] {
        [0x00] + string(name, huffman: huffman) + string(value, huffman: huffman)
    }

    /// §6.2.3 — literal never indexed: indexed name or new name.
    static func neverIndexed(name index: Int, value: String, huffman: Bool) -> [UInt8] {
        [0x10 | UInt8(index)] + string(value, huffman: huffman)
    }
    static func neverIndexed(newName name: String, value: String, huffman: Bool) -> [UInt8] {
        [0x10] + string(name, huffman: huffman) + string(value, huffman: huffman)
    }

    /// §6.3 — a dynamic table size update.
    static func sizeUpdate(_ size: Int) -> [UInt8] { [0x20 | UInt8(size)] }

    // Static-table indices used below: 2 = :method GET, 6 = :scheme http, 4 = :path / (RFC 7541 App. A).
    /// A complete indexed request line (:method GET, :scheme http, :path /).
    static let base: [UInt8] = indexed(2) + indexed(6) + indexed(4)
    /// :method + :scheme only — for cases where :path comes from the representation under test.
    static let methodScheme: [UInt8] = indexed(2) + indexed(6)
}
