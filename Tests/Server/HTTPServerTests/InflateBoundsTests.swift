//
//  InflateBoundsTests.swift
//  HTTPServerTests
//
//  ``Inflate`` as a *bounded, incremental, validating* decoder (RFC 1950 / 1951 / 1952, CWE-409).
//  Three properties the one-shot `maxOutput + 1` buffer could not provide: the configured cap is a
//  refusal threshold rather than an allocation, an arithmetically extreme cap does not trap, and a
//  zlib wrapper is verified — header and Adler-32 — instead of being stripped on faith.
//

import Compression
import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTPServer

@Suite("Inflate — bounded, incremental, validated (RFC 1950/1951/1952, CWE-409)")
struct InflateBoundsTests {
    // MARK: The cap is a threshold, not an allocation

    @Test("a cap far above the real output does not become the allocation")
    func capIsNotPreallocated() throws {
        // The finding, exactly: a small coded body under a default-scale cap. The old decoder sized
        // one buffer to `maxOutput + 1` before decoding, so this allocated a gigabyte to produce
        // 768 octets.
        let original = Array(String(repeating: "small body. ", count: 64).utf8)
        let coded = try #require(Gzip.compress(original))
        var decoded: [UInt8]?
        _ = Inflate.decompress(coded, encoding: "gzip", maxOutput: 1 << 20)  // warm up
        expectAllocatedBytes(noMoreThan: 1 << 20) {
            decoded = Inflate.decompress(coded, encoding: "gzip", maxOutput: 1 << 30)
        }
        #expect(decoded == original)
    }

    @Test("a bomb fails closed without ever materializing its expansion")
    func bombFailsClosedWithinTheCap() throws {
        // 16 MiB of zeros in a few KiB of gzip, against a 1 MiB cap. It must refuse, and the refusal
        // must cost about the cap — not the 16 MiB the member would expand to.
        let coded = try #require(Gzip.compress([UInt8](repeating: 0, count: 16 << 20)))
        var decoded: [UInt8]? = []
        _ = Inflate.decompress(coded, encoding: "gzip", maxOutput: 1 << 10)  // warm up
        expectAllocatedBytes(noMoreThan: 8 << 20) {
            decoded = Inflate.decompress(coded, encoding: "gzip", maxOutput: 1 << 20)
        }
        #expect(decoded == nil)
    }

    @Test(
        "an arithmetically extreme cap is handled, not trapped",
        arguments: [Int.max, Int.max - 1, Int.max / 2]
    )
    func extremeCapDoesNotTrap(maxOutput: Int) throws {
        // `maxOutput + 1` overflowed and trapped here; a decoder reachable from a public initializer
        // must never let its own bound become the crash.
        let original = Array("bounded".utf8)
        let coded = try #require(Gzip.compress(original))
        #expect(Inflate.decompress(coded, encoding: "gzip", maxOutput: maxOutput) == original)
    }

    @Test("output exactly at the cap is accepted, one octet past it is refused")
    func capBoundaryIsExact() throws {
        let original = Array(String(repeating: "z", count: 1_000).utf8)
        let coded = try #require(Gzip.compress(original))
        #expect(Inflate.decompress(coded, encoding: "gzip", maxOutput: 1_000) == original)
        #expect(Inflate.decompress(coded, encoding: "gzip", maxOutput: 999) == nil)
    }

    @Test("a non-positive cap admits nothing", arguments: [0, -1, Int.min])
    func nonPositiveCapAdmitsNothing(maxOutput: Int) throws {
        let coded = try #require(Gzip.compress(Array("anything".utf8)))
        #expect(Inflate.decompress(coded, encoding: "gzip", maxOutput: maxOutput) == nil)
    }

    // MARK: The zlib wrapper is validated, not assumed

    @Test("a well-formed zlib-wrapped deflate body decodes (RFC 1950)")
    func zlibWrappedDeflateDecodes() {
        let original = Array(String(repeating: "zlib wrapped. ", count: 40).utf8)
        let coded = Self.zlibWrapped(original)
        #expect(Inflate.decompress(coded, encoding: "deflate", maxOutput: 1 << 16) == original)
    }

    @Test("a raw deflate body still decodes (RFC 1951 — the common HTTP spelling)")
    func rawDeflateStillDecodes() {
        let original = Array(String(repeating: "raw deflate. ", count: 40).utf8)
        let coded = Self.rawDeflate(original)
        #expect(Inflate.decompress(coded, encoding: "deflate", maxOutput: 1 << 16) == original)
    }

    @Test("a zlib header failing the FCHECK multiple-of-31 rule is refused (RFC 1950 §2.2)")
    func badFCheckRefused() {
        var coded = Self.zlibWrapped(Array(String(repeating: "fcheck. ", count: 40).utf8))
        coded[1] ^= 0x01  // FCHECK lives in the low bits of FLG; one flip breaks the %31 == 0 rule
        #expect(Inflate.decompress(coded, encoding: "deflate", maxOutput: 1 << 16) == nil)
    }

    @Test("a zlib header whose CM is not 8 is refused (RFC 1950 §2.2)")
    func nonDeflateCompressionMethodRefused() {
        var coded = Self.zlibWrapped(Array(String(repeating: "method. ", count: 40).utf8))
        // CM = 7 with FLG re-chosen so the header still satisfies the %31 == 0 rule: the refusal must
        // come from the method itself, not incidentally from the check bits.
        coded[0] = (coded[0] & 0xF0) | 0x07
        coded[1] = Self.fcheckCorrected(cmf: coded[0], flg: coded[1])
        #expect(Inflate.decompress(coded, encoding: "deflate", maxOutput: 1 << 16) == nil)
    }

    @Test("a zlib header requesting a preset dictionary (FDICT) is refused (RFC 1950 §2.2)")
    func presetDictionaryRefused() {
        var coded = Self.zlibWrapped(Array(String(repeating: "fdict. ", count: 40).utf8))
        coded[1] |= 0x20  // FDICT
        coded[1] = Self.fcheckCorrected(cmf: coded[0], flg: coded[1])
        #expect(Inflate.decompress(coded, encoding: "deflate", maxOutput: 1 << 16) == nil)
    }

    @Test("a corrupted Adler-32 trailer is refused, not mis-decoded (RFC 1950 §2.2, §9)")
    func corruptedAdlerRefused() {
        var coded = Self.zlibWrapped(Array(String(repeating: "adler. ", count: 40).utf8))
        coded[coded.count - 2] ^= 0xFF
        #expect(Inflate.decompress(coded, encoding: "deflate", maxOutput: 1 << 16) == nil)
    }

    @Test("a truncated zlib stream is refused")
    func truncatedZlibRefused() {
        let coded = Self.zlibWrapped(Array(String(repeating: "truncate. ", count: 40).utf8))
        #expect(
            Inflate.decompress(Array(coded.dropLast(8)), encoding: "deflate", maxOutput: 1 << 16)
                == nil
        )
    }

    // MARK: Fixtures

    /// `input` as raw DEFLATE (RFC 1951) — what Apple's `COMPRESSION_ZLIB` actually produces.
    private static func rawDeflate(_ input: [UInt8]) -> [UInt8] {
        let capacity = input.count + input.count / 2 + 128
        var destination = [UInt8](repeating: 0, count: capacity)
        let written = input.withUnsafeBufferPointer { source -> Int in
            destination.withUnsafeMutableBufferPointer { output -> Int in
                guard let source = source.baseAddress, let output = output.baseAddress else {
                    return 0
                }
                return compression_encode_buffer(
                    output, capacity, source, input.count, nil, COMPRESSION_ZLIB
                )
            }
        }
        destination.removeLast(destination.count - written)
        return destination
    }

    /// `input` as a zlib stream (RFC 1950): CMF/FLG, the raw DEFLATE payload, and the big-endian
    /// Adler-32 of the *uncompressed* input.
    private static func zlibWrapped(_ input: [UInt8]) -> [UInt8] {
        var coded: [UInt8] = [0x78, 0x9C]  // CM = 8, CINFO = 7, no FDICT, FCHECK correct
        coded.append(contentsOf: rawDeflate(input))
        let adler = Adler32.checksum(input)
        for shift in stride(from: 24, through: 0, by: -8) {
            coded.append(UInt8(truncatingIfNeeded: adler >> UInt32(shift)))
        }
        return coded
    }

    /// `flg` with its low five FCHECK bits set so `(cmf << 8 | flg) % 31 == 0` (RFC 1950 §2.2).
    private static func fcheckCorrected(cmf: UInt8, flg: UInt8) -> UInt8 {
        let base = UInt16(cmf) << 8 | UInt16(flg & 0xE0)
        return (flg & 0xE0) | UInt8(30 - (base % 31) + 1) % 31
    }
}
