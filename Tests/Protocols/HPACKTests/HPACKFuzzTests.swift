//
//  HPACKFuzzTests.swift
//  HPACKTests
//
//  Seeded fuzzing for the RFC 7541 HPACK codec. The decoder reads untrusted header blocks off an
//  HTTP/2 connection, so it must NEVER trap, hang, or exhaust memory: it may only return fields or
//  throw a typed `HPACKError` — for the §5.1 prefix integers (truncation, overflow), the §5.2 string
//  literals (length lies, Huffman EOS / bad padding), the §6 representations (dead indices, table
//  size updates) and the §4.4 eviction rules alike. Reaching the end of a run is the assertion;
//  fixed seeds keep any failure reproducible.
//
//  The dynamic table is a ring buffer with two absolute-sequence hash indices (see
//  HPACKDynamicTable.swift), so the churn suites here drive eviction at tiny table sizes on purpose:
//  a ring/index desync hides exactly where entries wrap, evict and re-insert, which is why the
//  model-based test re-verifies every lookup after every operation and the round-trip test pins the
//  encoder's and decoder's tables to logical equality after every block.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HPACK

@Suite("Fuzzing — RFC 7541 HPACK codec never traps", .tags(.fuzz))
struct HPACKFuzzTests {
    private static let churnSeeds: [UInt64] = [1, 2, 3, 5, 8, 13, 21, 34]

    private let iterations = 4_000

    // MARK: - Decoder over adversarial bytes

    @Test
    func `the decoder tolerates arbitrary random bytes and keeps its table bounded`() {
        var rng = SeededRNG(named: "hpack.decoder.random")
        var decoder = HPACKDecoder(maxDynamicTableSize: 256)
        for _ in 0 ..< iterations {
            let blob = randomBytes(&rng, maxLength: 301)
            _ = try? decode(&decoder, blob)
            // Bounded memory: whatever garbage the persistent decoder accepted, its table honours
            // its own cap (§4.4), and no size update ever raised that cap past the negotiated
            // maximum (§6.3).
            #expect(decoder.dynamicTable.size <= decoder.dynamicTable.maxSize)
            #expect(decoder.dynamicTable.maxSize <= 256)
        }
    }

    @Test
    func `the decoder tolerates mutated valid blocks mixing updates, Huffman and table refs`() {
        let report = fuzzNeverTraps(
            seed: .named("hpack.decoder.mutated"),
            iterations: iterations,
            corpus: corpusBlock,
            exercise: decodeWithFreshDecoder
        )
        #expect(report.iterations == iterations)
    }

    /// One malformed wire vector and the precise typed error it must produce.
    private struct Vector: Sendable, CustomStringConvertible {
        let description: String
        let bytes: [UInt8]
        let expected: HPACKError
    }

    /// The §5.1 / §5.2 / §6 malformed shapes — each must throw its exact error, none may trap.
    private static let vectors: [Vector] = [
        Vector(
            description: "truncated prefix integer (RFC 7541 §5.1)",
            bytes: [0xFF],
            expected: .truncatedInteger
        ),
        Vector(
            description: "prefix-integer continuation overflowing Int (§5.1)",
            bytes: [0xFF, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
            expected: .integerOverflow
        ),
        Vector(
            description: "string length longer than the remaining octets (§5.2)",
            bytes: [0x00, 0x05, 0x61],
            expected: .truncatedString
        ),
        Vector(
            description: "declared string length beyond maxFieldSize (§5.2)",
            // 0x10 = never-indexed literal, then a §5.1 7-bit prefix integer declaring a 20,000
            // octet name (127 + 33 + 27×128 + 1×16,384) against the default 16 KiB maxFieldSize.
            bytes: [0x10, 0x7F, 0xA1, 0x9B, 0x01],
            expected: .stringTooLong
        ),
        Vector(
            description: "Huffman payload that is nothing but EOS bits (§5.2)",
            bytes: [0x00, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            expected: .invalidHuffman
        ),
        Vector(
            description: "Huffman padding of zero bits instead of EOS ones (§5.2)",
            bytes: [0x00, 0x81, 0x18],
            expected: .invalidHuffman
        ),
        Vector(
            description: "indexed field with the impossible index 0 (§6.1)",
            bytes: [0x80],
            expected: .invalidIndex
        ),
        Vector(
            description: "indexed field addressing an empty dynamic table (§2.3.3)",
            bytes: [0xBE],
            expected: .invalidIndex
        ),
        Vector(
            description: "literal whose name index addresses no entry (§6.2.1)",
            bytes: [0x7E],
            expected: .invalidIndex
        ),
        Vector(
            description: "table size update after a field (§4.2)",
            bytes: [0x82, 0x20],
            expected: .invalidTableSizeUpdate
        ),
        Vector(
            description: "a third table size update in one block (§4.2)",
            bytes: [0x20, 0x20, 0x20],
            expected: .invalidTableSizeUpdate
        ),
        Vector(
            description: "table size update above the negotiated maximum (§6.3)",
            bytes: [0x3F, 0x8D, 0x02],
            expected: .invalidTableSizeUpdate
        )
    ]

    @Test(arguments: vectors)
    private func `a malformed representation throws its precise typed error`(vector: Vector) {
        var decoder = HPACKDecoder(maxDynamicTableSize: 256)
        #expect(throws: vector.expected) {
            _ = try decode(&decoder, vector.bytes)
        }
    }

    // MARK: - Eviction churn against a reference model (ring + hash-index desync oracle)

    /// The RFC 7541 §4 semantics restated as a plain newest-first array — the reference the ring
    /// buffer and its hash indices are checked against after every operation.
    private struct TableModel {
        var entries: [HPACKField] = []
        var size = 0
        var maxSize: Int

        mutating func add(_ field: HPACKField) {
            evict(untilRoomFor: field.tableSize)
            guard field.tableSize <= maxSize else {
                return  // an entry larger than the whole table empties it (§4.4)
            }
            entries.insert(field, at: 0)
            size += field.tableSize
        }

        mutating func setMaxSize(_ newMaxSize: Int) {
            maxSize = newMaxSize
            evict(untilRoomFor: 0)
        }

        private mutating func evict(untilRoomFor incoming: Int) {
            while let oldest = entries.last, size + incoming > maxSize {
                size -= oldest.tableSize
                entries.removeLast()
            }
        }
    }

    @Test(arguments: churnSeeds)
    func `random add and resize churn keeps the ring and its hash indices in agreement`(
        seed: UInt64
    ) {
        var rng = SeededRNG(seed: seed)
        var table = HPACKDynamicTable(maxSize: 128)  // 2–3 entries live → wrap + evict constantly
        var model = TableModel(maxSize: 128)
        let pool = churnPool()
        for _ in 0 ..< 1_000 {
            if rng.below(5) == 0 {
                let newMaxSize = rng.below(161)
                table.setMaxSize(newMaxSize)
                model.setMaxSize(newMaxSize)
            }
            else {
                let field = rng.pick(pool)
                table.add(field)
                model.add(field)
            }
            #expect(firstDisagreement(table, model, pool) == nil)
        }
    }

    /// A small pool with deliberate name/value duplicates (the index maps' overwrite paths) and one
    /// field too large for the table (the §4.4 empty-the-table path).
    private func churnPool() -> [HPACKField] {
        var pool: [HPACKField] = [
            HPACKField(name: "x-big", value: String(repeating: "v", count: 160))
        ]
        for name in 0 ..< 4 {
            for value in 0 ..< 3 {
                pool.append(HPACKField(name: "x-c\(name)", value: "v\(name)-\(value)"))
            }
        }
        return pool
    }

    /// The first way `table` disagrees with `model`, or nil when they agree everywhere.
    private func firstDisagreement(
        _ table: HPACKDynamicTable,
        _ model: TableModel,
        _ pool: [HPACKField]
    ) -> String? {
        guard table.count == model.entries.count, table.size == model.size else {
            return "count/size \(table.count)/\(table.size), "
                + "expected \(model.entries.count)/\(model.size)"
        }
        let base = HPACKStaticTable.count + 1
        for position in 0 ..< model.entries.count
        where table.field(at: base + position) != model.entries[position] {
            return "field(at: \(base + position)) diverged from the model"
        }
        guard table.field(at: base + model.entries.count) == nil else {
            return "index \(base + model.entries.count) resolved past the newest-first window"
        }
        for probe in pool {
            let exact = model.entries.firstIndex(of: probe).map { base + $0 }
            if table.index(of: probe) != exact {
                return "index(of: \(probe.name)) == \(String(describing: table.index(of: probe))), "
                    + "expected \(String(describing: exact))"
            }
            let named = model.entries.firstIndex { $0.name == probe.name }.map { base + $0 }
            if table.index(forName: probe.name) != named {
                return "index(forName: \(probe.name)) diverged from the model"
            }
        }
        return nil
    }

    // MARK: - Encoder to decoder round-trip under a tiny table

    @Test(arguments: churnSeeds)
    func `encoder to decoder round-trip under a tiny table reproduces every header list`(
        seed: UInt64
    ) throws {
        var rng = SeededRNG(seed: seed)
        var encoder = HPACKEncoder(maxDynamicTableSize: 128)
        var decoder = HPACKDecoder(maxDynamicTableSize: 128)
        let pool = fieldPool()
        for _ in 0 ..< 400 {
            let fields = randomFields(pool, &rng)
            let block = encoder.encode(fields)
            #expect(try decode(&decoder, block) == fields)
            // The lock-step invariant RFC 7541 §6 rests on: after every block the encoder's table
            // and the decoder's are logically identical — the cross-implementation desync oracle.
            #expect(encoder.dynamicTable == decoder.dynamicTable)
        }
    }

    @Test
    func `never-indexed literals round-trip and leave the dynamic table untouched`() throws {
        var rng = SeededRNG(named: "hpack.never-indexed")
        var decoder = HPACKDecoder(maxDynamicTableSize: 128)
        let pool = fieldPool()
        for _ in 0 ..< 400 {
            let fields = randomFields(pool, &rng)
            #expect(try decode(&decoder, neverIndexedBlock(fields)) == fields)
            // §6.2.3: a sensitive field must never enter the shared compression context.
            #expect(decoder.dynamicTable.isEmpty)
        }
    }

    /// Encodes `fields` as §6.2.3 never-indexed literals (the encoder has no sensitive-field API,
    /// so the representation a privacy-aware peer emits is assembled by hand).
    private func neverIndexedBlock(_ fields: [HPACKField]) -> [UInt8] {
        var block: [UInt8] = []
        for field in fields {
            HPACKInteger.encode(0, prefixBits: 4, firstByte: 0x10, into: &block)
            HPACKString.encode(field.name.utf8, into: &block)
            HPACKString.encode(field.value.utf8, into: &block)
        }
        return block
    }

    /// A pool mirroring the QPACK fuzz suite's: static-exact entries that never insert, custom
    /// fields that churn the dynamic table, and one field larger than the whole table (§4.4).
    private func fieldPool() -> [HPACKField] {
        var pool: [HPACKField] = [
            HPACKField(name: ":method", value: "GET"),  // static-exact — one indexed octet
            HPACKField(name: "content-type", value: "application/json"),  // static name reference
            HPACKField(name: "x-large", value: String(repeating: "v", count: 160))  // wipes §4.4
        ]
        for name in 0 ..< 6 {
            for value in 0 ..< 3 {
                pool.append(HPACKField(name: "x-h\(name)", value: "v\(name)-\(value)"))
            }
        }
        return pool
    }

    private func randomFields(_ pool: [HPACKField], _ rng: inout SeededRNG) -> [HPACKField] {
        var fields: [HPACKField] = []
        for _ in 0 ..< (1 + rng.below(4)) {
            fields.append(rng.pick(pool))
        }
        return fields
    }

    // MARK: - Shared plumbing

    /// A valid block: two leading §6.3 size updates, literals with incremental indexing (one value
    /// Huffman-coded), a static indexed field, a dynamic indexed reference, and a §6.2.3
    /// never-indexed literal — every representation the mutation engine can then corrupt.
    private func corpusBlock() -> [UInt8] {
        var block: [UInt8] = []
        HPACKInteger.encode(0, prefixBits: 5, firstByte: 0x20, into: &block)  // §6.3 evict-all
        HPACKInteger.encode(128, prefixBits: 5, firstByte: 0x20, into: &block)  // §6.3 restore
        var encoder = HPACKEncoder(maxDynamicTableSize: 128)
        let indexed = HPACKField(name: "x-fuzz", value: "huffman friendly value")
        encoder.encode(indexed, into: &block)  // literal w/ incremental indexing, Huffman value
        encoder.encode(HPACKField(name: ":method", value: "GET"), into: &block)  // static indexed
        encoder.encode(indexed, into: &block)  // now a dynamic indexed reference
        HPACKInteger.encode(0, prefixBits: 4, firstByte: 0x10, into: &block)  // §6.2.3 sensitive
        HPACKString.encode("authorization".utf8, into: &block)
        HPACKString.encode("Bearer 12345".utf8, into: &block)
        return block
    }

    private func decodeWithFreshDecoder(_ bytes: [UInt8]) {
        var decoder = HPACKDecoder(maxDynamicTableSize: 256)
        _ = try? decode(&decoder, bytes)
    }

    private func decode(
        _ decoder: inout HPACKDecoder,
        _ block: [UInt8]
    ) throws -> [HPACKField] {
        try block.withUnsafeBytes { try decoder.decode($0.bytes) }
    }

    private func randomBytes(_ rng: inout SeededRNG, maxLength: Int) -> [UInt8] {
        let length = rng.below(maxLength)
        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        for _ in 0 ..< length {
            bytes.append(rng.byte())
        }
        return bytes
    }
}
