//
//  ChunkedDecoder.swift
//  HTTP1
//
//  RFC 9112 §7.1 — the chunked transfer-coding decoder. Iterative (no recursion); chunk data is
//  copied once into the assembled body (chunks are necessarily discontiguous). Hostile sizes are
//  rejected: hex chunk-sizes are overflow-checked and the total body is bounded by ``HTTPLimits``.
//

public import HTTPCore

/// Decodes the HTTP/1.1 chunked transfer-coding (RFC 9112 §7.1).
public enum ChunkedDecoder {

    private static let carriageReturn: UInt8 = 0x0D
    private static let lineFeed: UInt8 = 0x0A
    private static let semicolon: UInt8 = 0x3B

    /// Decodes the chunked body starting at `reader` (size CRLF data CRLF … last-chunk trailers
    /// CRLF), advancing past it, and returns the assembled body — or throws an ``HTTP1ParseError``.
    public static func decode(
        _ reader: inout ByteReader,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> [UInt8] {
        var body = [UInt8]()
        while true {
            guard let sizeLine = reader.readSlice(until: carriageReturn) else {
                throw .incompleteBody
            }
            guard let sizeLineFeed = reader.readByte() else { throw .incompleteBody }
            guard sizeLineFeed == lineFeed else { throw .malformedChunk }

            let size = try parseChunkSize(reader.slice(in: sizeLine))
            if size == 0 {
                try consumeTrailers(&reader, limits: limits)
                return body
            }

            // Compare without computing `body.count + size`, which would TRAP on a hostile
            // chunk-size near `Int.max`. `body.count <= maxBodySize` holds by construction, so the
            // subtraction never underflows.
            guard size <= limits.maxBodySize - body.count else { throw .bodyTooLarge }
            let dataStart = reader.position
            guard reader.remaining >= size else { throw .incompleteBody }
            reader.advance(by: size)
            reader.slice(in: dataStart..<(dataStart + size)).withUnsafeBytes {
                body.append(contentsOf: $0)
            }
            // Each chunk-data is followed by CRLF (RFC 9112 §7.1). Too few octets means the CRLF has
            // not arrived yet (incomplete), not that the framing is wrong (malformed).
            guard reader.remaining >= 2 else { throw .incompleteBody }
            guard reader.readByte() == carriageReturn, reader.readByte() == lineFeed else {
                throw .malformedChunk
            }
        }
    }

    /// Parses `chunk-size = 1*HEXDIG` from a size line, stopping at a chunk-ext `;` (RFC 9112 §7.1).
    ///
    /// Overflow-checked: a hex value that would exceed `Int` is rejected rather than wrapping.
    private static func parseChunkSize(_ line: RawSpan) throws(HTTP1ParseError) -> Int {
        let count = line.byteCount
        var size = 0
        var index = 0
        var sawDigit = false
        while index < count {
            let byte = line.unsafeLoad(fromByteOffset: index, as: UInt8.self)
            if byte == semicolon { break }  // chunk extensions begin; ignore the rest
            guard let digit = hexValue(byte) else { throw .invalidChunkSize }
            let (scaled, scaleOverflow) = size.multipliedReportingOverflow(by: 16)
            guard !scaleOverflow else { throw .invalidChunkSize }
            let (sum, addOverflow) = scaled.addingReportingOverflow(digit)
            guard !addOverflow else { throw .invalidChunkSize }
            size = sum
            sawDigit = true
            index += 1
        }
        guard sawDigit else { throw .invalidChunkSize }
        return size
    }

    /// Consumes the optional trailer section after the last chunk, up to the terminating empty line.
    private static func consumeTrailers(
        _ reader: inout ByteReader,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) {
        var totalSize = 0
        while true {
            guard let first = reader.peek() else { throw .incompleteBody }
            if first == carriageReturn {
                _ = reader.readByte()  // CR
                guard let emptyLineFeed = reader.readByte() else { throw .incompleteBody }
                guard emptyLineFeed == lineFeed else { throw .malformedChunk }
                return
            }
            guard let lineRange = reader.readSlice(until: carriageReturn) else {
                throw .incompleteBody
            }
            guard let trailerLineFeed = reader.readByte() else { throw .incompleteBody }
            guard trailerLineFeed == lineFeed else { throw .malformedChunk }
            totalSize += lineRange.count + 2
            guard totalSize <= limits.maxHeaderListSize else { throw .headerSectionTooLarge }
        }
    }

    /// The value of a single hexadecimal digit, or `nil` if `byte` is not a HEXDIG.
    private static func hexValue(_ byte: UInt8) -> Int? {
        switch byte {
        case 0x30...0x39: Int(byte - 0x30)  // 0-9
        case 0x41...0x46: Int(byte - 0x41 + 10)  // A-F
        case 0x61...0x66: Int(byte - 0x61 + 10)  // a-f
        default: nil
        }
    }
}
