//
//  MultipartFuzzTests.swift
//  HTTPCoreTests
//
//  Deterministic fuzzing for the RFC 7578 `multipart/form-data` parser and its RFC 2046 §5.1.1
//  delimiter grammar. The parser reads an attacker-controlled upload body, so it must NEVER trap,
//  hang, or grow without bound: a malformed or hostile body returns `nil`, and reaching the end of a
//  run (the process did not crash) is the assertion; fixed seeds keep any failure reproducible.
//
//  The adversarial shapes are seeded from the two defect classes addendum P0.6 fixed: boundary-prefix
//  bytes planted inside part bodies (the forged part split, CWE-444) and partial-prefix / junk-suffix
//  floods (superlinear matcher cost, CWE-407). The cost bound is asserted on the matcher's
//  deterministic byte-comparison count, never on wall-clock time. The parser is single-shot over a
//  borrowed span — there is no incremental feed — so "buffer seams" here are placement extremes: a
//  delimiter at offset zero (no preamble), a close-delimiter at end-of-body with no trailing CRLF,
//  and the mutation engine's truncate/extend edits landing mid-delimiter.
//

import HTTPTestSupport
import Testing

@testable import HTTPCore

/// The boundary the mutated-corpus exercise parses with (file-scope, shared with the corpus).
private let referenceBoundary = "fuzz-B0"

/// The lines of a valid three-part reference body: preamble, transport padding, an empty part, a
/// file part whose payload plants a junk-suffixed delimiter (the P0.6 forged-split shape), and an
/// epilogue.
private let referenceLines = [
    "preamble to be skipped",
    "--fuzz-B0",
    "Content-Disposition: form-data; name=\"note\"",
    "",
    "hello world",
    "--fuzz-B0 \t",
    "Content-Disposition: form-data; name=\"empty\"",
    "",
    "",
    "--fuzz-B0",
    "Content-Disposition: form-data; name=\"file\"; filename=\"a.bin\"",
    "Content-Type: application/octet-stream",
    "",
    "binary\u{00}bytes",
    "--fuzz-B0junk",
    "--fuzz-B0--",
    "epilogue"
]

/// The reference body the mutation engine corrupts, joined with the CRLF RFC 2046 mandates.
private let referenceBody: [UInt8] = Array(referenceLines.joined(separator: "\r\n").utf8)

/// Parses `bytes` against the reference boundary, discarding the result — only a trap fails.
private func parseReferenceBody(_ bytes: [UInt8]) {
    _ = MultipartFormData.parse(bytes, boundary: referenceBoundary)
}

/// Parses `body` with the internal parser and reports the matcher's byte-comparison count.
private func measureComparisons(
    _ body: [UInt8],
    boundary: String
) -> (form: MultipartFormData?, compares: Int) {
    guard let validated = MultipartBoundary(boundary) else {
        return (nil, 0)
    }
    return body.withUnsafeBytes { raw in
        var parser = MultipartParser(
            body: raw.bytes,
            boundary: validated,
            limits: MultipartLimits()
        )
        let form = parser.parse()
        return (form, parser.byteComparisons)
    }
}

@Suite("Fuzzing — RFC 7578 multipart/form-data parser never traps", .tags(.fuzz))
struct MultipartFuzzTests {
    private static let roundTripSeeds: [UInt64] = [1, 2, 3, 5, 8, 13, 21, 34]

    private let iterations = 4_000

    // MARK: - Random and mutated bytes

    @Test
    func `the parser tolerates arbitrary random bytes under default and tight limits`() {
        var rng = SeededRNG(named: "multipart.random")
        let tight = MultipartLimits(maxParts: 2, maxPartHeaderBytes: 48, maxRetainedBytes: 64)
        let boundaries = [
            "B",
            "----WebKitFormBoundary7MA4YWxkTrZu0gW",
            String(repeating: "z", count: 70)
        ]
        for _ in 0 ..< iterations {
            let body = randomBytes(&rng, maxLength: 301)
            let boundary = rng.pick(boundaries)
            _ = MultipartFormData.parse(body, boundary: boundary)
            _ = MultipartFormData.parse(body, boundary: boundary, limits: tight)
        }
    }

    @Test
    func `the parser tolerates a mutated valid multi-part body`() {
        let report = fuzzNeverTraps(
            seed: .named("multipart.mutated"),
            iterations: iterations,
            corpus: { referenceBody },
            exercise: parseReferenceBody
        )
        #expect(report.iterations == iterations)
    }

    // MARK: - Round-trip under adversarial payloads

    @Test(arguments: roundTripSeeds)
    func `serialize then parse round-trips planted prefixes and nested boundaries`(seed: UInt64) {
        var rng = SeededRNG(seed: seed)
        for _ in 0 ..< 150 {
            let boundary = randomBoundary(&rng, first: "o")
            let parts = randomParts(&rng, boundary: boundary)
            let body = serialize(
                parts,
                boundary: boundary,
                preamble: rng.bool(),
                epilogue: rng.bool()
            )
            let reparsed = MultipartFormData.parse(body, boundary: boundary)
            #expect(reparsed == MultipartFormData(parts: parts))
        }
    }

    @Test(arguments: [11, 22] as [UInt64])
    func `bare-LF line endings and a missing close-delimiter fail closed`(seed: UInt64) {
        var rng = SeededRNG(seed: seed)
        for _ in 0 ..< 200 {
            let boundary = randomBoundary(&rng, first: "o")
            let parts = randomParts(&rng, boundary: boundary)
            // RFC 2046 §5.1.1 spells the delimiter `CRLF dash-boundary`: a body whose structural
            // line breaks are all bare LF contains no delimiter at all, however many parts it drew.
            let bareLF = serialize(parts, boundary: boundary, newline: "\n")
            #expect(MultipartFormData.parse(bareLF, boundary: boundary) == nil)
            // A body whose last part is never closed is malformed — no partial form may leak out.
            let unclosed = serialize(parts, boundary: boundary, close: false)
            #expect(MultipartFormData.parse(unclosed, boundary: boundary) == nil)
        }
    }

    @Test
    func `any form returned under random tight limits honours those limits`() {
        var rng = SeededRNG(named: "multipart.limits")
        for _ in 0 ..< 400 {
            let boundary = randomBoundary(&rng, first: "o")
            let body = serialize(randomParts(&rng, boundary: boundary), boundary: boundary)
            let limits = MultipartLimits(
                maxParts: rng.below(5),
                maxPartHeaderBytes: rng.below(97),
                maxRetainedBytes: rng.below(513)
            )
            guard let form = MultipartFormData.parse(body, boundary: boundary, limits: limits)
            else {
                continue  // fail-closed is always an acceptable outcome under a breached limit
            }
            #expect(form.parts.count <= limits.maxParts)
            #expect(retainedBytes(of: form) <= limits.maxRetainedBytes)
        }
    }

    @Test
    func `a doubled delimiter line becomes part content, never a phantom part`() {
        // The first delimiter consumes its own trailing CRLF, so the second `--dup` line is not
        // preceded by a CRLF of its own and RFC 2046 §5.1.1 makes it ordinary body-part content —
        // here a junk header line the next part's header scan ignores.
        let lines = [
            "--dup", "Content-Disposition: form-data; name=\"a\"", "", "1",
            "--dup", "--dup", "Content-Disposition: form-data; name=\"b\"", "", "2",
            "--dup--", ""
        ]
        let body = Array(lines.joined(separator: "\r\n").utf8)
        let form = MultipartFormData.parse(body, boundary: "dup")
        #expect(form?.parts.count == 2)
        #expect(form?["a"]?.body == Array("1".utf8))
        #expect(form?["b"]?.body == Array("2".utf8))
    }

    // MARK: - Bounded cost on malformed floods (the P0.6 superlinear class)

    @Test
    func `malformed adversarial floods stay linear in byte comparisons`() {
        let boundary = String(repeating: "f", count: 64)
        let opening = "--\(boundary)\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n"
        // Partial-prefix runs (67 of 68 delimiter bytes, then a miss) and junk-suffixed full
        // matches, with no close-delimiter anywhere: the parser must reject BOTH bodies after one
        // KMP pass, at most two comparisons per byte — a property of the algorithm, so the bound is
        // deterministic where a wall-clock ratio would flake under load.
        let nearMiss = "\r\n--" + String(repeating: "f", count: 63) + "X"
        let junkSuffix = "\r\n--" + boundary + "JUNK"
        for payload in [nearMiss, junkSuffix] {
            let body = Array((opening + String(repeating: payload, count: 2_000)).utf8)
            let (form, compares) = measureComparisons(body, boundary: boundary)
            #expect(form == nil)
            #expect(compares <= 2 * body.count)
        }
    }

    @Test
    func `a rejected junk-suffix flood allocates only the boundary's own arrays`() {
        let boundary = String(repeating: "f", count: 64)
        let flood = String(repeating: "\r\n--" + boundary + "JUNK", count: 2_000)
        let body = Array(("--\(boundary)\r\n" + flood).utf8)
        _ = MultipartFormData.parse(body, boundary: boundary)  // warm one-time lazy initialization
        expectAllocations(noMoreThan: 10) {
            _ = MultipartFormData.parse(body, boundary: boundary)
        }
    }

    // MARK: - Seeded generators

    /// `length` random bytes (`0 ..< maxLength`), any value.
    private func randomBytes(_ rng: inout SeededRNG, maxLength: Int) -> [UInt8] {
        let length = rng.below(maxLength)
        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        for _ in 0 ..< length {
            bytes.append(rng.byte())
        }
        return bytes
    }

    /// A random valid boundary opening with `first`, so outer and nested inner boundaries (drawn
    /// with different openers) can never be prefixes of one another.
    private func randomBoundary(_ rng: inout SeededRNG, first: Character) -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789")
        var boundary = String(first)
        for _ in 0 ..< (11 + rng.below(12)) {
            boundary.append(alphabet[rng.below(alphabet.count)])
        }
        return boundary
    }

    /// A random `token`-safe name of `length` characters (quote-free, so round-trips unescaped).
    private func randomToken(_ rng: inout SeededRNG, length: Int) -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789_-")
        var token = ""
        for _ in 0 ..< length {
            token.append(alphabet[rng.below(alphabet.count)])
        }
        return token
    }

    /// Random payload bytes with planted boundary-prefix runs — the P0.6 forged-split class.
    ///
    /// A full-length plant is always followed by a junk byte: a full plant at the payload's very end
    /// would abut the serializer's real CRLF and become a genuine delimiter, the one placement the
    /// grammar itself is required to split on.
    private func randomPartBody(_ rng: inout SeededRNG, boundary: String) -> [UInt8] {
        let boundaryBytes = Array(boundary.utf8)
        var body: [UInt8] = []
        for _ in 0 ..< rng.below(5) {
            switch rng.below(3) {
                case 0:  // a run of arbitrary bytes, CR and LF included
                    body += randomBytes(&rng, maxLength: 33)
                case 1:  // a planted `CRLF "--"` + boundary prefix
                    body += Array("\r\n--".utf8)
                    let length = 1 + rng.below(boundaryBytes.count)
                    body += boundaryBytes.prefix(length)
                    if length == boundaryBytes.count {
                        body.append(0x4A)  // "J" — a junk byte no delimiter suffix admits
                    }
                default:  // structural noise: bare CRLFs and dash runs
                    body += Array("\r\n----\r\n".utf8)
            }
        }
        return body
    }

    /// 1–4 random parts; occasionally a part's body is a whole nested inner multipart body.
    private func randomParts(
        _ rng: inout SeededRNG,
        boundary: String
    ) -> [MultipartFormData.Part] {
        var parts: [MultipartFormData.Part] = []
        for _ in 0 ..< (1 + rng.below(4)) {
            let body: [UInt8]
            if rng.below(6) == 0 {
                let inner = randomBoundary(&rng, first: "i")
                let innerPart = MultipartFormData.Part(
                    name: "inner",
                    body: randomPartBody(&rng, boundary: inner)
                )
                body = serialize([innerPart], boundary: inner)
            }
            else {
                body = randomPartBody(&rng, boundary: boundary)
            }
            parts.append(
                MultipartFormData.Part(
                    name: randomToken(&rng, length: 1 + rng.below(10)),
                    filename: rng.bool() ? randomToken(&rng, length: 4) + ".bin" : nil,
                    contentType: rng.bool() ? "application/octet-stream" : nil,
                    body: body
                )
            )
        }
        return parts
    }

    /// Serializes `parts` in the RFC 2046 §5.1.1 wire form; `newline` lets a caller break the
    /// grammar, and `close: false` drops the terminal `close-delimiter` entirely.
    private func serialize(
        _ parts: [MultipartFormData.Part],
        boundary: String,
        newline: String = "\r\n",
        preamble: Bool = false,
        epilogue: Bool = false,
        close: Bool = true
    ) -> [UInt8] {
        var out: [UInt8] = []
        if preamble {
            out += Array("this preamble is not a part\(newline)".utf8)
        }
        for part in parts {
            out += Array("--\(boundary)\(newline)".utf8)
            var disposition = "Content-Disposition: form-data; name=\"\(part.name)\""
            if let filename = part.filename {
                disposition += "; filename=\"\(filename)\""
            }
            out += Array("\(disposition)\(newline)".utf8)
            if let contentType = part.contentType {
                out += Array("Content-Type: \(contentType)\(newline)".utf8)
            }
            out += Array(newline.utf8)
            out += part.body
            out += Array(newline.utf8)
        }
        if close {
            out += Array("--\(boundary)--".utf8)
            if epilogue {
                out += Array("\(newline)this epilogue is not a part".utf8)
            }
        }
        return out
    }

    /// The bytes `form` actually retains — the quantity ``MultipartLimits/maxRetainedBytes`` caps.
    private func retainedBytes(of form: MultipartFormData) -> Int {
        form.parts.reduce(0) { total, part in
            total + part.body.count + part.name.utf8.count + (part.filename?.utf8.count ?? 0)
                + (part.contentType?.utf8.count ?? 0)
        }
    }
}
