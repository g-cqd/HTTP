//
//  HTTPVersion.swift
//  HTTP1
//
//  RFC 9112 §2.3 — the HTTP version token on the HTTP/1.x wire.
//

/// An HTTP protocol version as written on the HTTP/1.x wire (RFC 9112 §2.3).
///
/// `HTTP-version = "HTTP" "/" DIGIT "." DIGIT` — the major and minor numbers are single decimal
/// digits. HTTP/2 and HTTP/3 carry no version token, so this type is specific to HTTP/1.x.
public struct HTTPVersion: Sendable, Hashable {

    /// The major version number (a single digit, e.g. `1`).
    public let major: Int

    /// The minor version number (a single digit, e.g. `1`).
    public let minor: Int

    /// Creates a version from explicit major and minor numbers.
    public init(major: Int, minor: Int) {
        self.major = major
        self.minor = minor
    }

    /// Parses a version token such as `"HTTP/1.1"`, returning `nil` if it is malformed.
    public init?(parsing text: String) {
        let utf8 = text.utf8
        guard utf8.count == 8 else { return nil }
        var iterator = utf8.makeIterator()
        // "HTTP/"
        guard iterator.next() == 0x48, iterator.next() == 0x54, iterator.next() == 0x54,
            iterator.next() == 0x50, iterator.next() == 0x2F
        else { return nil }
        guard let majorByte = iterator.next(), majorByte >= 0x30, majorByte <= 0x39 else {
            return nil
        }
        guard iterator.next() == 0x2E else { return nil }  // "."
        guard let minorByte = iterator.next(), minorByte >= 0x30, minorByte <= 0x39 else {
            return nil
        }
        self.major = Int(majorByte - 0x30)
        self.minor = Int(minorByte - 0x30)
    }

    /// `HTTP/1.0` (RFC 9112).
    public static let http10 = HTTPVersion(major: 1, minor: 0)

    /// `HTTP/1.1` (RFC 9112).
    public static let http11 = HTTPVersion(major: 1, minor: 1)
}

extension HTTPVersion: CustomStringConvertible {

    /// The wire form, e.g. `"HTTP/1.1"`.
    public var description: String {
        "HTTP/\(major).\(minor)"
    }
}
