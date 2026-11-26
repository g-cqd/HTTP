//
//  HeaderSectionWriter.swift
//  HTTP1
//
//  RFC 9112 §5 — appends a header section (`field-name ": " field-value CRLF`… then the blank line)
//  to an outbound message buffer. Shared by the request and response serializers so both
//  directions emit fields through one path.
//

internal import HTTPCore

/// Writes an HTTP/1.1 header section onto the wire (RFC 9112 §5).
enum HeaderSectionWriter {
    static let crlf: [UInt8] = [0x0D, 0x0A]
    static let space: UInt8 = 0x20
    private static let colon: UInt8 = 0x3A

    /// Appends every field of `fields`, then the blank line that terminates the section.
    static func append(_ fields: HTTPFields, to output: inout [UInt8]) {
        for field in fields {
            field.name.appendRawNameUTF8(to: &output)
            output.append(colon)
            output.append(space)
            output.append(contentsOf: field.value.utf8)
            output.append(contentsOf: crlf)
        }
        output.append(contentsOf: crlf)  // blank line terminates the header section
    }
}
