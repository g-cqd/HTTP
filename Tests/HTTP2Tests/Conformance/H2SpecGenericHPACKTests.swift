//
//  H2SpecGenericHPACKTests.swift
//  HTTP2Tests
//
//  h2spec conformance — the `generic` group, §5 HPACK: the engine MUST accept a request whose header
//  block uses each RFC 7541 §6 field representation. Each case hand-encodes one representation (indexed,
//  literal ± incremental indexing, literal without indexing, literal never indexed, dynamic table size
//  update — raw and Huffman) into a complete, valid request and asserts it decodes to a `.request`.
//  The raw blocks are built on the public canonical `Huffman` codec (HTTPCore) so the ±Huffman variants
//  are exercised deterministically rather than left to the encoder's shorter-of-the-two choice.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

/// Supplies `:path` (static index 4) via the representation under test, on an otherwise-indexed line.
private func hpackPath(_ make: (Int, String, Bool) -> [UInt8], _ huffman: Bool) -> [UInt8] {
    H2HPACK.methodScheme + make(4, "/a", huffman)
}

/// Appends one new-name field (via the representation under test) to an otherwise-indexed valid request.
private func hpackExtra(_ make: (String, String, Bool) -> [UInt8], _ huffman: Bool) -> [UInt8] {
    H2HPACK.base + make("custom-key", "custom-value", huffman)
}

/// The 15 RFC 7541 §6 representations the generic group requires a server to accept.
///
/// Built as a typed top-level constant (not inline in `@Test`) so the compiler type-checks each block
/// quickly; `hpackPath(...)` supplies `:path` (static index 4) via a literal, `hpackExtra(...)` appends
/// one new-name field to an otherwise-indexed valid request.
private let hpackRepresentations: [(label: String, block: [UInt8])] = [
    (label: "indexed", block: H2HPACK.base),
    (
        label: "incremental indexing, indexed name",
        block: hpackPath(H2HPACK.incremental(name:value:huffman:), false)
    ),
    (
        label: "incremental indexing, indexed name (Huffman)",
        block: hpackPath(H2HPACK.incremental(name:value:huffman:), true)
    ),
    (
        label: "incremental indexing, new name",
        block: hpackExtra(H2HPACK.incremental(newName:value:huffman:), false)
    ),
    (
        label: "incremental indexing, new name (Huffman)",
        block: hpackExtra(H2HPACK.incremental(newName:value:huffman:), true)
    ),
    (
        label: "without indexing, indexed name",
        block: hpackPath(H2HPACK.withoutIndexing(name:value:huffman:), false)
    ),
    (
        label: "without indexing, indexed name (Huffman)",
        block: hpackPath(H2HPACK.withoutIndexing(name:value:huffman:), true)
    ),
    (
        label: "without indexing, new name",
        block: hpackExtra(H2HPACK.withoutIndexing(newName:value:huffman:), false)
    ),
    (
        label: "without indexing, new name (Huffman)",
        block: hpackExtra(H2HPACK.withoutIndexing(newName:value:huffman:), true)
    ),
    (
        label: "never indexed, indexed name",
        block: hpackPath(H2HPACK.neverIndexed(name:value:huffman:), false)
    ),
    (
        label: "never indexed, indexed name (Huffman)",
        block: hpackPath(H2HPACK.neverIndexed(name:value:huffman:), true)
    ),
    (
        label: "never indexed, new name",
        block: hpackExtra(H2HPACK.neverIndexed(newName:value:huffman:), false)
    ),
    (
        label: "never indexed, new name (Huffman)",
        block: hpackExtra(H2HPACK.neverIndexed(newName:value:huffman:), true)
    ),
    (label: "dynamic table size update", block: H2HPACK.sizeUpdate(0) + H2HPACK.base),
    (
        label: "multiple dynamic table size updates",
        block: H2HPACK.sizeUpdate(0) + H2HPACK.sizeUpdate(10) + H2HPACK.base
    )
]

@Suite("h2spec generic §5 — HPACK representations accepted")
struct H2SpecGenericHPACKTests {
    @Test(
        "generic 5 — the engine accepts each HPACK field representation (RFC 7541 §6)",
        arguments: hpackRepresentations)
    func acceptsHPACKRepresentation(_ testCase: (label: String, block: [UInt8])) throws {
        var connection = try H2Wire.handshaked()
        let wire = H2Wire.frame(
            .headers,
            flags: [.endHeaders, .endStream],
            streamID: 1,
            payload: testCase.block
        )
        H2Wire.expectRequest(wire, on: &connection)
    }

    // h2spec coverage: §5 HPACK = 15 representation cases.
}
