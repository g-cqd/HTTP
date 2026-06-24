//
//  HeaderField.swift
//  HTTPCore
//
//  A header field name/value pair, shared by HPACK (RFC 7541, HTTP/2) and QPACK (RFC 9204, HTTP/3).
//  Both compression layers model a field identically — a pair of octet strings — and both size a
//  dynamic-table entry the same way (name + value + 32, RFC 7541 §4.1 / RFC 9204 §3.2.1). Hoisting
//  the type here lets the two codecs and the two request mappers share one representation instead of
//  each declaring their own and converting at the boundary.
//

/// A header field name/value pair, as the header-compression layers model it (RFC 7541 §1.3 /
/// RFC 9204 §3.1).
///
/// Pseudo-header names (`":path"`, `":status"`, …) are not HTTP/1.1 tokens, so the compression layer
/// keeps fields as plain strings and the HTTP/2 and HTTP/3 layers map them onto
/// ``HTTPRequest``/``HTTPResponse`` pseudo-headers and ``HTTPFields``.
public struct HeaderField: Sendable, Equatable, Hashable {
    /// The field name (lower-case on the wire; may be a pseudo-header such as `":method"`).
    public let name: String

    /// The field value (possibly empty).
    public let value: String

    /// Creates a field from a name and an optional value.
    public init(name: String, value: String = "") {
        self.name = name
        self.value = value
    }

    /// The entry's size for dynamic-table accounting: name octets + value octets + 32
    /// (RFC 7541 §4.1 / RFC 9204 §3.2.1).
    ///
    /// The constant 32 is the RFC's estimate of per-entry overhead, charged so the table bound also
    /// limits the number of entries an attacker can pin in memory.
    public var tableSize: Int {
        name.utf8.count + value.utf8.count + 32
    }
}
