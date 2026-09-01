//
//  InflateVectorTests.swift
//  HTTPDeflateTests
//
//  RFC 1951 §3.2.x edge vectors, handcrafted bit by bit so they are independent of both this
//  codec's encoder and zlib's: stored-block framing (§3.2.4), the fixed code with the 258-length
//  match and distance-1 run (§3.2.5/§3.2.6), the dynamic header at its HLIT/HDIST maxima and every
//  §3.2.7 rejection shape (reserved BTYPE, bad NLEN, over-subscribed and incomplete alphabets,
//  repeat misuse, missing end-of-block, reserved symbols, too-far distances).
//

internal import HTTPDeflate
import Testing

@Suite("RFC 1951 §3.2 — handcrafted inflate vectors")
struct InflateVectorTests {
    /// Pumps `input` through a fresh raw inflater.
    private func inflate(
        _ input: [UInt8], limit: Int = 1 << 20
    ) throws(InflateError) -> (bytes: [UInt8], progress: CodecProgress) {
        var inflator = Inflator()
        var output: [UInt8] = []
        let progress = try inflator.pump(input, appendingTo: &output, limit: limit)
        return (output, progress)
    }

    // MARK: Stored blocks (§3.2.4)

    @Test("the empty stored final block decodes to nothing and finishes")
    func emptyStoredFinal() throws {
        let result = try inflate([0x01, 0x00, 0x00, 0xFF, 0xFF])
        #expect(result.bytes.isEmpty)
        #expect(result.progress == .finished)
    }

    @Test("a stored block passes its octets through verbatim")
    func storedPassthrough() throws {
        let result = try inflate([0x01, 0x03, 0x00, 0xFC, 0xFF, 0x61, 0x62, 0x63])
        #expect(result.bytes == [0x61, 0x62, 0x63])
        #expect(result.progress == .finished)
    }

    @Test("a non-final stored block chains into the next block header")
    func storedThenFinal() throws {
        // Stored "ab" (BFINAL 0), then the empty stored final block.
        let input: [UInt8] = [
            0x00, 0x02, 0x00, 0xFD, 0xFF, 0x61, 0x62,
            0x01, 0x00, 0x00, 0xFF, 0xFF
        ]
        let result = try inflate(input)
        #expect(result.bytes == [0x61, 0x62])
        #expect(result.progress == .finished)
    }

    @Test("NLEN that is not LEN's complement is rejected (§3.2.4)")
    func storedLengthMismatch() {
        #expect(throws: InflateError.invalidStoredLength) {
            _ = try inflate([0x01, 0x03, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63])
        }
    }

    @Test("the reserved block type BTYPE=11 is rejected (§3.2.3)")
    func reservedBlockType() {
        #expect(throws: InflateError.invalidBlockType) {
            _ = try inflate([0x07])
        }
    }

    // MARK: Fixed code (§3.2.6), the 258 match and the distance-1 run (§3.2.5)

    @Test("a 258-length distance-1 match expands against the fixed code")
    func maxLengthDistanceOneRun() throws {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)  // BFINAL
        stream.bits(1, 2)  // BTYPE 01
        stream.code(48 + 0x61, 8)  // literal 'a'
        stream.code(0xC5, 8)  // symbol 285 → length 258, no extra
        stream.code(0, 5)  // distance code 0 → distance 1
        stream.code(0, 7)  // end of block
        let result = try inflate(stream.output)
        #expect(result.bytes == [UInt8](repeating: 0x61, count: 259))
        #expect(result.progress == .finished)
    }

    @Test("a distance past the start of output is rejected (§3.2.5)")
    func distanceTooFar() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(1, 2)
        stream.code(48 + 0x61, 8)  // one octet written
        stream.code(1, 7)  // symbol 257 → length 3
        stream.code(1, 5)  // distance code 1 → distance 2 > 1 written
        #expect(throws: InflateError.distanceTooFar) {
            _ = try inflate(stream.output)
        }
    }

    @Test("the reserved distance codes 30/31 are rejected (§3.2.5)")
    func reservedDistanceCode() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(1, 2)
        stream.code(48 + 0x61, 8)
        stream.code(1, 7)  // length 3
        stream.code(30, 5)  // reserved distance code
        #expect(throws: InflateError.invalidSymbol) {
            _ = try inflate(stream.output)
        }
    }

    @Test("the reserved literal/length codes 286/287 are rejected (§3.2.5)")
    func reservedLiteralCode() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(1, 2)
        stream.code(0xC6, 8)  // symbol 286
        #expect(throws: InflateError.invalidSymbol) {
            _ = try inflate(stream.output)
        }
    }

    // MARK: Dynamic headers (§3.2.7)

    @Test("HLIT past 286 is rejected (§3.2.7)")
    func literalCountOverflow() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(2, 2)  // BTYPE 10
        stream.bits(30, 5)  // HLIT → 287 codes
        stream.bits(0, 5)
        stream.bits(0, 4)
        #expect(throws: InflateError.invalidCodeCounts) {
            _ = try inflate(stream.output)
        }
    }

    @Test("HDIST past 30 is rejected (§3.2.7)")
    func distanceCountOverflow() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(2, 2)
        stream.bits(0, 5)
        stream.bits(30, 5)  // HDIST → 31 codes
        stream.bits(0, 4)
        #expect(throws: InflateError.invalidCodeCounts) {
            _ = try inflate(stream.output)
        }
    }

    @Test("an over-subscribed code-length code is rejected (§3.2.7)")
    func overSubscribedCodeLengthCode() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(2, 2)
        stream.bits(0, 5)
        stream.bits(0, 5)
        stream.bits(15, 4)  // HCLEN → all 19 lengths follow
        for _ in 0 ..< 19 { stream.bits(1, 3) }  // nineteen 1-bit codes
        #expect(throws: InflateError.invalidCodeLengthCode) {
            _ = try inflate(stream.output)
        }
    }

    @Test("a leading copy-previous repeat with nothing to copy is rejected (§3.2.7)")
    func repeatWithoutPrevious() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(2, 2)
        stream.bits(0, 5)
        stream.bits(0, 5)
        stream.bits(0, 4)  // HCLEN → the first 4 permuted lengths: 16, 17, 18, 0
        stream.bits(1, 3)  // symbol 16 → 1 bit
        stream.bits(0, 3)
        stream.bits(0, 3)
        stream.bits(1, 3)  // symbol 0 → 1 bit
        stream.code(1, 1)  // canonical: 0 → '0', 16 → '1'; emit 16 first
        stream.bits(0, 2)  // its repeat count
        #expect(throws: InflateError.invalidRepeat) {
            _ = try inflate(stream.output)
        }
    }

    @Test("a zero-repeat overrunning the declared symbol count is rejected (§3.2.7)")
    func repeatOverrun() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(2, 2)
        stream.bits(0, 5)  // 257 literal codes
        stream.bits(0, 5)  // 1 distance code
        stream.bits(0, 4)  // lengths for 16, 17, 18, 0
        stream.bits(0, 3)
        stream.bits(0, 3)
        stream.bits(1, 3)  // symbol 18 → 1 bit
        stream.bits(1, 3)  // symbol 0 → 1 bit
        stream.code(1, 1)  // canonical: 0 → '0', 18 → '1'
        stream.bits(127, 7)  // zero ×138
        stream.code(1, 1)
        stream.bits(127, 7)  // zero ×138 → 276 > 258
        #expect(throws: InflateError.invalidRepeat) {
            _ = try inflate(stream.output)
        }
    }

    @Test("a literal/length code with no end-of-block symbol is rejected (§3.2.7)")
    func missingEndOfBlock() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(2, 2)
        stream.bits(0, 5)
        stream.bits(0, 5)
        stream.bits(0, 4)  // lengths for 16, 17, 18, 0
        stream.bits(0, 3)
        stream.bits(0, 3)
        stream.bits(1, 3)  // symbol 18 → 1 bit
        stream.bits(1, 3)  // symbol 0 → 1 bit
        stream.code(1, 1)  // zero ×138
        stream.bits(127, 7)
        stream.code(1, 1)  // zero ×120 → all 258 lengths zero
        stream.bits(109, 7)
        #expect(throws: InflateError.invalidLiteralLengthCode) {
            _ = try inflate(stream.output)
        }
    }

    @Test("an incomplete literal/length alphabet is rejected (§3.2.7)")
    func incompleteLiteralCode() {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(2, 2)
        stream.bits(0, 5)  // 257 literal codes
        stream.bits(0, 5)  // 1 distance code
        stream.bits(13, 4)  // HCLEN 17 → permuted lengths through symbol 2
        // Code-length code: 18 → 1 bit, 0 → 2 bits, 2 → 2 bits (complete).
        let permuted: [(symbol: Int, length: Int)] = [
            (16, 0), (17, 0), (18, 1), (0, 2), (8, 0), (7, 0), (9, 0), (6, 0), (10, 0),
            (5, 0), (11, 0), (4, 0), (12, 0), (3, 0), (13, 0), (2, 2), (14, 0)
        ]
        for entry in permuted { stream.bits(entry.length, 3) }
        // Canonical: 18 → '0'; 0 → '10'; 2 → '11'.
        stream.code(3, 2)  // literal 0 gets length 2
        stream.code(0, 1)  // zero ×138
        stream.bits(127, 7)
        stream.code(0, 1)  // zero ×117
        stream.bits(106, 7)
        stream.code(3, 2)  // symbol 256 gets length 2 → two 2-bit codes: incomplete
        stream.code(2, 2)  // the lone distance length: a single zero
        #expect(throws: InflateError.invalidLiteralLengthCode) {
            _ = try inflate(stream.output)
        }
    }

    @Test("a maximal dynamic header (HLIT 286, HDIST 30, HCLEN 19) decodes (§3.2.7)")
    func maximalDynamicHeader() throws {
        var stream = DeflateCorpus.BitStream()
        stream.bits(1, 1)
        stream.bits(2, 2)
        stream.bits(29, 5)  // HLIT → 286
        stream.bits(29, 5)  // HDIST → 30
        stream.bits(15, 4)  // HCLEN → 19
        // Code-length code: {0: 2, 1: 2, 2: 2, 18: 2} — complete.
        let lengths = [Int](repeating: 0, count: 19)
        var bySymbol = lengths
        bySymbol[0] = 2
        bySymbol[1] = 2
        bySymbol[2] = 2
        bySymbol[18] = 2
        let order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
        for symbol in order { stream.bits(bySymbol[symbol], 3) }
        // Canonical code-length codes: 0 → '00', 1 → '01', 2 → '10', 18 → '11'.
        // Literals: symbol 0 length 1; 255 zeros; symbol 256 length 2; 28 zeros; symbol 285
        // length 2 (Kraft: 1/2 + 1/4 + 1/4 = 1, complete).
        stream.code(1, 2)  // literal 0 → length 1
        stream.code(3, 2)  // 18: zero ×138
        stream.bits(127, 7)
        stream.code(3, 2)  // 18: zero ×117
        stream.bits(106, 7)
        stream.code(2, 2)  // symbol 256 → length 2
        stream.code(3, 2)  // 18: zero ×28
        stream.bits(17, 7)
        stream.code(2, 2)  // symbol 285 → length 2
        // Distances: code 0 length 1; 28 zeros; code 29 length 1 (complete).
        stream.code(1, 2)
        stream.code(3, 2)  // 18: zero ×28
        stream.bits(17, 7)
        stream.code(1, 2)
        // Content: literal 0 ('0'), then end of block ('10').
        stream.code(0, 1)
        stream.code(2, 2)
        let result = try inflate(stream.output)
        #expect(result.bytes == [0x00])
        #expect(result.progress == .finished)
    }

    @Test("truncated input reports needsInput, not an error")
    func truncatedInputSuspends() throws {
        let whole: [UInt8] = [0x01, 0x03, 0x00, 0xFC, 0xFF, 0x61, 0x62, 0x63]
        for cut in 0 ..< whole.count {
            let result = try inflate(Array(whole[0 ..< cut]))
            #expect(result.progress == .needsInput, "cut at \(cut)")
        }
    }
}
