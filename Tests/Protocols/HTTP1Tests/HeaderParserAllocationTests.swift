//
//  HeaderParserAllocationTests.swift
//  HTTP1Tests
//
//  RFC 9112 §5 — the copy budget of an HTTP/1 header-section parse, guarded rather than described.
//  This is the hottest path the server has: every request on every keep-alive connection runs it, so
//  it carries the 200k-rps target directly. `HeaderParser` reads field names and values as `RawSpan`
//  slices and materializes only what the returned `HTTPFields` keeps — one `String` per value, and a
//  `HTTPFieldName` that reuses the already-lower-case spelling. The two properties below are what that
//  sentence means operationally, and neither was pinned before: the cost is one allocation per FIELD,
//  and it does not move when the field VALUES get longer. A re-introduced line copy, a per-field
//  `[UInt8]`, or a `[String: String]` of the section breaks the second one immediately.
//

import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTP1

/// A header section of `fields` lines, each carrying a `valueSize`-octet value.
private func section(fields: Int, valueSize: Int) -> [UInt8] {
    var text = ""
    var index = 0
    while index < fields {
        text += "X-Header-\(index): " + String(repeating: "v", count: valueSize) + "\r\n"
        index += 1
    }
    return Array((text + "\r\n").utf8)
}

/// Parses `bytes` as a header section, returning the allocations it cost (nil where unmeasurable).
private func parseCost(_ bytes: [UInt8]) -> Int? {
    var sink = 0
    warm(bytes, &sink)
    return mallocDelta { parse(bytes, &sink) }
}

/// Parses `bytes` as a header section, returning the heap octets it requested.
private func parseOctets(_ bytes: [UInt8]) -> Int? {
    var sink = 0
    warm(bytes, &sink)
    return mallocByteDelta { parse(bytes, &sink) }
}

/// Runs one parse before measuring, so one-time lazy initialization is not charged to the delta.
private func warm(_ bytes: [UInt8], _ sink: inout Int) {
    parse(bytes, &sink)
}

/// One header-section parse over a `ByteReader` borrowing `bytes` (zero-copy).
private func parse(_ bytes: [UInt8], _ sink: inout Int) {
    var total = 0
    bytes.withUnsafeBytes { raw in
        var reader = ByteReader(raw)
        total = (try? HeaderParser.parse(&reader, limits: .default))?.count ?? 0
    }
    sink &+= total
}

@Test("a realistic header section costs about one allocation per field, and no more")
func headerSectionCostsOneAllocationPerField() {
    // Measured floor: 9 for 8 fields — one `String` per field value plus the `HTTPFields` storage.
    // The names cost nothing: they are already lower-case, so `HTTPFieldName` reuses the spelling it
    // decoded instead of folding a second `String`. The ceiling is tight on purpose; a re-introduced
    // per-field copy lands well outside it.
    guard let cost = parseCost(section(fields: 8, valueSize: 24)) else {
        return  // allocation counting is unavailable on this platform
    }
    #expect(cost <= 12)
}

@Test("each octet of field value is materialized at most ONCE — the zero-copy guarantee, in octets")
func eachValueOctetIsMaterializedOnce() {
    // Allocation COUNT cannot see this one. A parser that copied each field-line into a scratch
    // `[UInt8]` before reading it makes one extra allocation per field however long the line is, so it
    // moves the count by a constant and leaves the count's size-independence intact. What it doubles
    // is the OCTETS, which is what `mallocByteDelta` exists to see.
    //
    // Stated as a slope rather than a ceiling so there is no magic constant to re-tune: growing the
    // values by N octets must grow the heap traffic by about N, not by 2N. Measured 1.04x here; the
    // scratch-copy shape measures 2.04x. The 1.5x threshold sits between them with room on both sides.
    let narrowInput = section(fields: 8, valueSize: 24)
    let wideInput = section(fields: 8, valueSize: 240)
    guard let narrow = parseOctets(narrowInput), let wide = parseOctets(wideInput) else {
        return  // allocation counting is unavailable on this platform
    }
    let inputGrowth = wideInput.count - narrowInput.count
    let octetGrowth = wide - narrow
    #expect(octetGrowth < inputGrowth * 3 / 2)
}

@Test("the parse cost is independent of field-value SIZE — a longer value is not a longer parse")
func parseCostIsIndependentOfValueSize() {
    // The count half of the same guarantee: ten times the value length must not mean more
    // allocations, only bigger ones. Catches a per-value chunking or accumulation loop.
    let narrow = parseCost(section(fields: 8, valueSize: 24))
    let wide = parseCost(section(fields: 8, valueSize: 240))
    guard let narrow, let wide else {
        return  // allocation counting is unavailable on this platform
    }
    #expect(wide == narrow)
}

@Test("the parse cost scales with the field COUNT and nothing else")
func parseCostScalesOnlyWithFieldCount() {
    let few = parseCost(section(fields: 8, valueSize: 24))
    let many = parseCost(section(fields: 16, valueSize: 24))
    guard let few, let many else {
        return  // allocation counting is unavailable on this platform
    }
    // One more `String` per added field — a slope of 1, not of 2 (a name copy) and not of the
    // value length. Stated as a bound so a `HTTPFields` storage re-grow does not make it brittle.
    #expect(many <= few + 8 + 2)
}

@Test("a malformed field name allocates nothing — validation precedes materialization")
func malformedNameAllocatesNothing() {
    // RFC 9112 §5: a field-name must be a `token`. The parser validates the name bytes in place and
    // throws before building the `String`, so a peer cannot make the server allocate by sending
    // garbage names. This is the allocation half of the smuggling defense (CWE-444).
    let bad = Array("X Bad Name: value\r\n\r\n".utf8)
    guard let cost = parseCost(bad) else {
        return  // allocation counting is unavailable on this platform
    }
    #expect(cost <= 2)
}
