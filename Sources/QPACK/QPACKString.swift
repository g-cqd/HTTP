//
//  QPACKString.swift
//  QPACK
//
//  RFC 9204 §4.1.2 — string literal representation: an `H` flag bit, a prefix-integer length, and that
//  many octets, optionally Huffman-coded with the canonical code shared from HTTPCore (RFC 7541 §5.2 /
//  Appendix B). Unlike HPACK, QPACK packs strings at two prefix widths — the value string uses a 7-bit
//  length prefix (H at bit 7), and the literal name of §4.5.6 uses a 3-bit prefix (H at bit 3) — so the
//  codec is parameterized by the prefix width; the `H` flag is always the bit just above the prefix.
//

public import HTTPCore

/// The RFC 9204 §4.1.2 string-literal codec (the RFC 7541 §5.2 representation, parameterized by prefix
/// width).
public enum QPACKString {
    /// Encodes `bytes` as a string literal, using the Huffman form only when it is shorter (§4.1.2).
    ///
    /// `firstByte` supplies the representation's fixed high bits (above the `H` flag); the codec sets
    /// the `H` flag — the bit at index `prefixBits` — when it chooses the Huffman form.
    public static func encode(
        _ bytes: some Collection<UInt8>,
        prefixBits: Int,
        firstByte: UInt8 = 0,
        into output: inout [UInt8]
    ) {
        let huffmanLength = Huffman.encodedByteLength(of: bytes)
        if huffmanLength < bytes.count {
            let flagged = firstByte | (1 << UInt8(prefixBits))
            QPACKInteger.encode(
                huffmanLength, prefixBits: prefixBits, firstByte: flagged, into: &output
            )
            Huffman.encode(bytes, into: &output)
        }
        else {
            QPACKInteger.encode(
                bytes.count, prefixBits: prefixBits, firstByte: firstByte, into: &output
            )
            output.append(contentsOf: bytes)
        }
    }

    /// Decodes a string literal from `reader` (RFC 9204 §4.1.2).
    ///
    /// The `H` flag is the bit at index `prefixBits`; the length is a `prefixBits`-bit prefix integer
    /// bounded by `maxEncodedLength`. A Huffman fault, oversized length, or truncation is a
    /// field-section decoding failure (`QPACK_DECOMPRESSION_FAILED`, RFC 9204 §6).
    public static func decodeString(
        _ reader: inout ByteReader,
        prefixBits: Int,
        maxEncodedLength: Int
    ) throws(QPACKError) -> String {
        guard let first = reader.peek() else { throw .decompressionFailed("truncated string") }
        let huffmanCoded = (first >> UInt8(prefixBits)) & 1 == 1
        let length: Int
        switch QPACKInteger.decode(&reader, prefixBits: prefixBits) {
            case .value(let value):
                length = value
            case .incomplete, .overflow:
                throw .decompressionFailed("invalid string length")
        }
        guard length <= maxEncodedLength else { throw .decompressionFailed("string too long") }
        guard reader.remaining >= length else { throw .decompressionFailed("truncated string") }
        let start = reader.position
        reader.advance(by: length)
        let payload = reader.slice(in: start ..< (start + length))
        if huffmanCoded {
            do { return try Huffman.decodeString(payload) }
            catch {
                throw .decompressionFailed("invalid Huffman")
            }
        }
        return payload.withUnsafeBytes { String(decoding: $0, as: Unicode.UTF8.self) }
    }
}
