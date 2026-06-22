//
//  HPACKField.swift
//  HPACK
//
//  RFC 7541 §1.3 — a header field as HPACK models it: a name/value pair of octet strings. Pseudo-
//  header names (":path", ":status", …) are not HTTP/1.1 tokens, so HPACK keeps fields as plain
//  strings and the HTTP/2 layer maps them onto HTTPRequest/HTTPResponse pseudo-headers and HTTPFields.
//

/// A header field name/value pair as represented inside HPACK (RFC 7541 §1.3).
public struct HPACKField: Sendable, Equatable, Hashable {

    /// The field name (lower-case on the wire; may be a pseudo-header such as ":method").
    public let name: String

    /// The field value (possibly empty).
    public let value: String

    /// Creates a field from a name and an optional value.
    public init(name: String, value: String = "") {
        self.name = name
        self.value = value
    }

    /// The entry's size for dynamic-table accounting: name octets + value octets + 32 (RFC 7541 §4.1).
    ///
    /// The constant 32 is the RFC's estimate of per-entry overhead, charged so the table bound also
    /// limits the number of entries an attacker can pin in memory.
    public var tableSize: Int {
        name.utf8.count + value.utf8.count + 32
    }
}
