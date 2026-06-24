//
//  HPACKString.swift
//  HPACK
//
//  RFC 7541 §5.2 — string literal representation: an `H` flag bit, a 7-bit prefix-integer length, and
//  that many octets, optionally Huffman-coded. The encoder chooses the Huffman form only when it is
//  strictly shorter (§5.2); the decoder bounds the declared length and maps any Huffman fault to a
//  fatal HPACK error.
//

public import HTTPCore

/// The RFC 7541 §5.2 string-literal codec.
public enum HPACKString {
    private static let huffmanFlag: UInt8 = 0x80

    /// Encodes `bytes` as a string literal, using the Huffman form only when it is shorter (§5.2).
    ///
    /// NOTE (Phase 1.4, measured): the length is probed with the cheap `Huffman.encodedByteLength`
    /// (a sum over `lengths[byte]`) *before* the expensive `Huffman.encode` bit-packing, so the
    /// raw-wins branch skips the encode entirely — that is why `hpack/String/encode-raw` (~4.38 µs)
    /// is cheaper than `hpack/String/encode` (~4.67 µs). Fusing the probe into a single encode pass
    /// would save the cheap probe on Huffman-wins but force a wasted encode + scratch allocation on
    /// raw-wins; not adopted — added complexity to pessimize the raw-wins branch for a marginal,
    /// mix-dependent gain. The `encode-raw` benchmark guards this.
    public static func encode(_ bytes: some Collection<UInt8>, into output: inout [UInt8]) {
        let huffmanLength = Huffman.encodedByteLength(of: bytes)
        if huffmanLength < bytes.count {
            HPACKInteger.encode(huffmanLength, prefixBits: 7, firstByte: huffmanFlag, into: &output)
            Huffman.encode(bytes, into: &output)
        }
        else {
            HPACKInteger.encode(bytes.count, prefixBits: 7, firstByte: 0, into: &output)
            output.append(contentsOf: bytes)
        }
    }

    /// Decodes a string literal from `reader` (RFC 7541 §5.2).
    ///
    /// The declared length is bounded by `maxEncodedLength` (fail closed on an oversized field), and a
    /// Huffman-coded payload is decoded through the shared canonical decoder.
    public static func decode(
        _ reader: inout ByteReader,
        maxEncodedLength: Int
    ) throws(HPACKError) -> [UInt8] {
        let (huffmanCoded, range) = try parseHeader(&reader, maxEncodedLength: maxEncodedLength)
        let payload = reader.slice(in: range)
        if huffmanCoded {
            do { return try Huffman.decode(payload) }
            catch { throw .invalidHuffman }
        }
        return payload.withUnsafeBytes { Array($0) }
    }

    /// Decodes a string literal straight into a `String` (RFC 7541 §5.2).
    ///
    /// Avoids the throwaway `[UInt8]` that ``decode(_:maxEncodedLength:)`` materializes — the HPACK
    /// decoder's hot path. Non-UTF-8 octets are repaired exactly as `String(decoding:as:)` does.
    public static func decodeString(
        _ reader: inout ByteReader,
        maxEncodedLength: Int
    ) throws(HPACKError) -> String {
        let (huffmanCoded, range) = try parseHeader(&reader, maxEncodedLength: maxEncodedLength)
        let payload = reader.slice(in: range)
        if huffmanCoded {
            do { return try Huffman.decodeString(payload) }
            catch { throw .invalidHuffman }
        }
        return payload.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
    }

    /// Parses the §5.2 string header (H flag + 7-bit length), bounds the declared length against
    /// `maxEncodedLength`, advances `reader` past the payload, and returns the Huffman flag and the
    /// payload's byte range within the reader.
    private static func parseHeader(
        _ reader: inout ByteReader,
        maxEncodedLength: Int
    ) throws(HPACKError) -> (huffmanCoded: Bool, range: Range<Int>) {
        guard let first = reader.peek() else { throw .truncatedString }
        let huffmanCoded = (first & huffmanFlag) != 0
        let length = try HPACKInteger.decode(&reader, prefixBits: 7)
        guard length <= maxEncodedLength else { throw .stringTooLong }
        guard reader.remaining >= length else { throw .truncatedString }
        let start = reader.position
        reader.advance(by: length)
        return (huffmanCoded, start ..< (start + length))
    }
}
