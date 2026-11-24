//
//  HeaderParser.swift
//  HTTP1
//
//  RFC 9112 §5 — parses the header section. Iterative (no recursion) and zero-copy: field names and
//  values are read as `RawSpan` slices and materialized only when stored. Enforces the smuggling
//  defenses (obs-fold rejection, no whitespace before the colon, strict CRLF) and the failsafe
//  ``HTTPLimits``.
//

internal import AemiKernel
public import HTTPCore

/// Parses the HTTP/1.1 header section (RFC 9112 §5).
public enum HeaderParser {
    private static let colon: UInt8 = 0x3A
    private static let space: UInt8 = 0x20
    private static let htab: UInt8 = 0x09
    private static let carriageReturn: UInt8 = 0x0D
    private static let lineFeed: UInt8 = 0x0A

    /// Parses field-lines from `reader` until the terminating empty line, advancing the reader past
    /// it, and returns the collected ``HTTPFields`` — or throws the specific ``HTTP1ParseError``.
    public static func parse(
        _ reader: inout HTTPCore.ByteReader,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> HTTPFields {
        var fields = HTTPFields()
        // Real header sections carry ~10–20 lines; reserve once so the append loop below never pays the
        // geometric [HTTPField] re-grows (each copying every field). See HTTPFields.reserveCapacity.
        fields.reserveCapacity(16)
        var totalSize = 0
        while true {
            guard let first = reader.peek() else { throw .incompleteHeaders }

            // The header section is terminated by an empty line (a CRLF on its own).
            if first == carriageReturn {
                _ = reader.readByte()  // CR
                guard reader.readByte() == lineFeed else { throw .malformedHeaders }
                return fields
            }
            // A line that begins with SP/HTAB is obsolete line folding — reject (RFC 9112 §5.2).
            if first == space || first == htab { throw .obsoleteLineFolding }

            guard let lineRange = reader.readSlice(until: carriageReturn) else {
                throw .incompleteHeaders
            }
            guard reader.readByte() == lineFeed else { throw .malformedHeaders }  // bare CR

            guard lineRange.count <= limits.maxFieldSize else { throw .fieldTooLarge }
            totalSize += lineRange.count + 2  // include the CRLF in the section-size budget
            guard totalSize <= limits.maxHeaderListSize else { throw .headerSectionTooLarge }
            guard fields.count < limits.maxFieldCount else { throw .tooManyFields }
            // Strict CRLF: a bare LF inside a field-line is a smuggling vector (RFC 9112 §2.2). The
            // field-value validator would also reject an embedded LF, but fail closed here explicitly.
            if reader.slice(in: lineRange).withUnsafeBytes({ unsafe $0.contains(lineFeed) }) {
                throw .malformedHeaders
            }
            fields.append(try parseFieldLine(reader.slice(in: lineRange)))
        }
    }

    /// Parses one `field-name ":" OWS field-value OWS` line (RFC 9112 §5), working directly on the
    /// borrowed `RawSpan` (zero-copy) and materializing the name and trimmed value only at the end.
    private static func parseFieldLine(_ line: RawSpan) throws(HTTP1ParseError) -> HTTPField {
        let count = line.byteCount

        var colonIndex = -1
        var index = 0
        while index < count {
            if line.loadU8(index) == colon {
                colonIndex = index
                break
            }
            index += 1
        }
        guard colonIndex >= 0 else { throw .missingColon }
        // A token field-name cannot be empty; a trailing OWS would also make it a non-token below.
        guard colonIndex > 0 else { throw .invalidFieldName }

        // Trim OWS (SP / HTAB) on both sides of the value (RFC 9112 §5).
        var valueStart = colonIndex + 1
        while valueStart < count,
            isOptionalWhitespace(line.loadU8(valueStart))
        {
            valueStart += 1
        }
        var valueEnd = count
        while valueEnd > valueStart,
            isOptionalWhitespace(line.loadU8(valueEnd - 1))
        {
            valueEnd -= 1
        }

        // Validate the name bytes before materializing: an invalid name never allocates a `String`.
        let fieldName = line.extracting(0 ..< colonIndex)
            .withUnsafeBytes { unsafe HTTPFieldName(validating: $0) }
        guard let fieldName else { throw .invalidFieldName }
        let value = line.extracting(valueStart ..< valueEnd)
            .withUnsafeBytes { unsafe String(decoding: $0, as: Unicode.UTF8.self) }
        guard let field = HTTPField(name: fieldName, value: value) else { throw .invalidFieldValue }
        return field
    }

    private static func isOptionalWhitespace(_ byte: UInt8) -> Bool {
        byte == space || byte == htab
    }
}
