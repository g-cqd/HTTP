//
//  DERReader.swift
//  HTTPTransport
//
//  A minimal, bounds-checked DER TLV cursor (ITU-T X.690) for the X.509 walks the transport layer
//  performs off the byte path (SAN extraction). Strictly linear: it reads one tag-length-value at a
//  time from a slice and never recurses; nested structures are walked by constructing a new reader
//  over a returned content slice. Every read is bounds-checked, multi-byte tags (X.690 §8.1.2.4) and
//  length-of-length beyond 4 octets are rejected, so hostile DER can neither over-read nor trap.
//

/// A bounds-checked cursor over DER TLV elements (ITU-T X.690).
struct DERReader {
    /// One decoded element: its tag octet and its content slice (indices into the original storage).
    struct Element {
        let tag: UInt8
        let content: ArraySlice<UInt8>
    }

    private let bytes: ArraySlice<UInt8>
    private var index: Int

    init(_ bytes: ArraySlice<UInt8>) {
        self.bytes = bytes
        self.index = bytes.startIndex
    }

    /// Reads the next TLV element, or `nil` at the end of the slice or on malformed DER (a multi-byte
    /// tag, an over-long length, or a length past the end).
    mutating func readElement() -> Element? {
        guard index < bytes.endIndex else {
            return nil
        }
        let tag = bytes[index]
        guard tag & 0x1F != 0x1F else {
            return nil  // multi-byte tag (X.690 §8.1.2.4) — never used by RFC 5280 structures
        }
        var cursor = index + 1
        guard let length = readLength(at: &cursor) else {
            return nil
        }
        guard length <= bytes.endIndex - cursor else {
            return nil  // declared length runs past the buffer — malformed / truncated
        }
        let content = bytes[cursor ..< cursor + length]
        index = cursor + length
        return Element(tag: tag, content: content)
    }

    /// Reads the next element and returns its content iff its tag matches (`0x30` for SEQUENCE).
    mutating func readConstructed(tag: UInt8) -> ArraySlice<UInt8>? {
        guard let element = readElement(), element.tag == tag else {
            return nil
        }
        return element.content
    }

    /// Decodes a DER length at `cursor` and advances it past the length octets (X.690 §8.1.3).
    ///
    /// Short form, or long form of ≤ 4 length octets (a certificate never exceeds 2³² − 1 octets).
    private func readLength(at cursor: inout Int) -> Int? {
        guard cursor < bytes.endIndex else {
            return nil
        }
        let first = bytes[cursor]
        cursor += 1
        if first & 0x80 == 0 {
            return Int(first)  // short form
        }
        let lengthOfLength = Int(first & 0x7F)
        guard lengthOfLength > 0, lengthOfLength <= 4,
            lengthOfLength <= bytes.endIndex - cursor
        else {
            return nil  // indefinite (forbidden in DER) or unreasonably long
        }
        var length = 0
        for _ in 0 ..< lengthOfLength {
            length = length << 8 | Int(bytes[cursor])
            cursor += 1
        }
        return length
    }
}
