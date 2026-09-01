//
//  ContainerTests.swift
//  HTTPDeflateTests
//
//  RFC 1952 / RFC 1950 container framing: every optional gzip header field (FEXTRA, FNAME,
//  FCOMMENT, FHCRC — assembled by hand around a known DEFLATE body), the reserved-bit and magic
//  rejections, both trailer checks failing closed, and the zlib envelope's header/Adler-32 error
//  shapes. Plus the Adler-32 reference vector.
//

internal import HTTPDeflate
import Testing

@Suite("RFC 1952 / RFC 1950 — container framing")
struct ContainerTests {
    /// A stored-block DEFLATE body for "abc", with the matching CRC-32 and ISIZE trailer values.
    private let body: [UInt8] = [0x01, 0x03, 0x00, 0xFC, 0xFF, 0x61, 0x62, 0x63]
    private let payload: [UInt8] = [0x61, 0x62, 0x63]
    /// CRC-32("abc") — the RFC 1952 §8 polynomial's standard value.
    private let payloadCRC: UInt32 = 0x3524_41C2

    private func member(
        flags: UInt8, fields: [UInt8], crc: UInt32? = nil, size: UInt32? = nil
    ) -> [UInt8] {
        var member: [UInt8] = [0x1F, 0x8B, 0x08, flags, 0, 0, 0, 0, 0, 0xFF]
        member.append(contentsOf: fields)
        member.append(contentsOf: body)
        appendLittleEndian(crc ?? payloadCRC, to: &member)
        appendLittleEndian(size ?? 3, to: &member)
        return member
    }

    private func appendLittleEndian(_ value: UInt32, to output: inout [UInt8]) {
        for shift in [0, 8, 16, 24] { output.append(UInt8((value >> shift) & 0xFF)) }
    }

    @Test("a plain member decodes and verifies both trailer fields")
    func plainMember() {
        #expect(
            DeflateCodec.decompress(member(flags: 0, fields: []), format: .gzip, capacity: 64)
                == payload
        )
    }

    @Test("FEXTRA, FNAME, FCOMMENT and combinations are skipped correctly (§2.3)")
    func optionalFields() {
        let extra: [UInt8] = [0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]  // XLEN=4 + payload
        let name = Array("file.txt".utf8) + [0]
        let comment = Array("a comment".utf8) + [0]
        let cases: [(UInt8, [UInt8])] = [
            (0x04, extra),
            (0x08, name),
            (0x10, comment),
            (0x04 | 0x08 | 0x10, extra + name + comment)
        ]
        for (flags, fields) in cases {
            #expect(
                DeflateCodec.decompress(
                    member(flags: flags, fields: fields), format: .gzip, capacity: 64
                ) == payload,
                "flags \(flags)"
            )
        }
    }

    @Test("an FEXTRA field with XLEN 0 is legal and skipped")
    func emptyExtraField() {
        #expect(
            DeflateCodec.decompress(
                member(flags: 0x04, fields: [0x00, 0x00]), format: .gzip, capacity: 64
            ) == payload
        )
    }

    @Test("FHCRC verifies the low 16 bits of the header CRC (§2.3.1)")
    func headerChecksum() {
        // CRC-32 of the 10 fixed header octets with FLG=0x02.
        var header: [UInt8] = [0x1F, 0x8B, 0x08, 0x02, 0, 0, 0, 0, 0, 0xFF]
        var crc = Self.referenceCRC(header)
        header.append(UInt8(crc & 0xFF))
        header.append(UInt8((crc >> 8) & 0xFF))
        var whole = header
        whole.append(contentsOf: body)
        appendLittleEndian(payloadCRC, to: &whole)
        appendLittleEndian(3, to: &whole)
        #expect(DeflateCodec.decompress(whole, format: .gzip, capacity: 64) == payload)
        // And the mismatch fails closed.
        crc ^= 0xFFFF
        var corrupted = Array(whole[0 ..< 10])
        corrupted.append(UInt8(crc & 0xFF))
        corrupted.append(UInt8((crc >> 8) & 0xFF))
        corrupted.append(contentsOf: whole[12...])
        #expect(DeflateCodec.decompress(corrupted, format: .gzip, capacity: 64) == nil)
    }

    @Test("bad magic, bad method, and reserved flag bits are rejected (§2.3)")
    func headerRejections() {
        var badMagic = member(flags: 0, fields: [])
        badMagic[0] = 0x1E
        #expect(DeflateCodec.decompress(badMagic, format: .gzip, capacity: 64) == nil)
        var badMethod = member(flags: 0, fields: [])
        badMethod[2] = 7
        #expect(DeflateCodec.decompress(badMethod, format: .gzip, capacity: 64) == nil)
        #expect(
            DeflateCodec.decompress(member(flags: 0x80, fields: []), format: .gzip, capacity: 64)
                == nil
        )
    }

    @Test("a wrong trailer CRC-32 or ISIZE fails closed (§2.3.1)")
    func trailerRejections() {
        #expect(
            DeflateCodec.decompress(
                member(flags: 0, fields: [], crc: payloadCRC ^ 1), format: .gzip, capacity: 64
            ) == nil
        )
        #expect(
            DeflateCodec.decompress(
                member(flags: 0, fields: [], size: 4), format: .gzip, capacity: 64
            ) == nil
        )
    }

    @Test("a truncated member (any prefix) is rejected, never partial output")
    func truncatedMember() {
        let whole = member(flags: 0, fields: [])
        for cut in 0 ..< whole.count {
            #expect(
                DeflateCodec.decompress(Array(whole[0 ..< cut]), format: .gzip, capacity: 64)
                    == nil,
                "cut \(cut)"
            )
        }
    }

    @Test("our encoder's members carry the deterministic fixed header")
    func encoderHeader() {
        let member = DeflateCodec.gzip(payload)
        #expect(Array(member[0 ..< 10]) == [0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0xFF])
    }

    // MARK: zlib envelopes (RFC 1950)

    @Test("zlib header rejections: bad check bits, bad method, FDICT (§2.2)")
    func zlibHeaderRejections() {
        let valid: [UInt8] = [0x78, 0x9C] + body + [0x02, 0x4D, 0x01, 0x27]
        #expect(DeflateCodec.decompress(valid, format: .zlib, capacity: 64) == payload)
        var badCheck = valid
        badCheck[1] = 0x9D  // breaks CMF·256 + FLG ≡ 0 (mod 31)
        #expect(DeflateCodec.decompress(badCheck, format: .zlib, capacity: 64) == nil)
        var badMethod = valid
        badMethod[0] = 0x79  // CM = 9
        #expect(DeflateCodec.decompress(badMethod, format: .zlib, capacity: 64) == nil)
        let dictionary: [UInt8] = [0x78, 0xBB]  // FDICT set, check bits valid
        #expect(
            DeflateCodec.decompress(dictionary + valid[2...], format: .zlib, capacity: 64) == nil
        )
    }

    @Test("a wrong Adler-32 fails closed (§2.2)")
    func zlibAdlerRejection() {
        let corrupted: [UInt8] = [0x78, 0x9C] + body + [0x02, 0x4D, 0x01, 0x28]
        #expect(DeflateCodec.decompress(corrupted, format: .zlib, capacity: 64) == nil)
    }

    /// A tiny, independent CRC-32 (reflected 0xEDB88320) for the FHCRC fixture.
    private static func referenceCRC(_ bytes: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0 ..< 8 {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1
            }
        }
        return crc ^ 0xFFFF_FFFF
    }
}
