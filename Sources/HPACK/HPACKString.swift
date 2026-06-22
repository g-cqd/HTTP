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
    public static func encode(_ bytes: some Collection<UInt8>, into output: inout [UInt8]) {
        let huffmanLength = Huffman.encodedByteLength(of: bytes)
        if huffmanLength < bytes.count {
            HPACKInteger.encode(huffmanLength, prefixBits: 7, firstByte: huffmanFlag, into: &output)
            output.append(contentsOf: Huffman.encode(bytes))
        } else {
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
        guard let first = reader.peek() else { throw .truncatedString }
        let huffmanCoded = (first & huffmanFlag) != 0
        let length = try HPACKInteger.decode(&reader, prefixBits: 7)
        guard length <= maxEncodedLength else { throw .stringTooLong }
        guard reader.remaining >= length else { throw .truncatedString }

        let start = reader.position
        reader.advance(by: length)
        let payload = reader.slice(in: start..<(start + length))
        if huffmanCoded {
            do {
                return try Huffman.decode(payload)
            } catch {
                throw .invalidHuffman
            }
        }
        return payload.withUnsafeBytes { Array($0) }
    }
}
