//
//  QPACKStaticTable.swift
//  QPACK
//
//  RFC 9204 Appendix A — the 99-entry QPACK static table, transcribed from the RFC text. Unlike HPACK
//  (RFC 7541 Appendix A: 61 entries addressed 1-based), the QPACK static table is **0-based** with 99
//  entries: index 0 is the first entry, index 98 the last. The dynamic and static tables are addressed
//  separately in QPACK (not one combined space), so this table is indexed directly by the value carried
//  in a `T=1` field-line representation (RFC 9204 §3.2.4 / §4.5.2). Getting the 0-based/99-entry math
//  right is essential — reusing HPACK's 1-based/61-entry offsets is a known interop trap.
//

public import HTTPCore

/// The RFC 9204 Appendix A static table — 99 entries, 0-based.
public enum QPACKStaticTable {
    /// The number of entries in the static table (RFC 9204 Appendix A).
    public static let count = 99

    /// The static table entries, addressed 0...98 directly (`entries[index]`).
    public static let entries: [HeaderField] = [
        HeaderField(name: ":authority"),
        HeaderField(name: ":path", value: "/"),
        HeaderField(name: "age", value: "0"),
        HeaderField(name: "content-disposition"),
        HeaderField(name: "content-length", value: "0"),
        HeaderField(name: "cookie"),
        HeaderField(name: "date"),
        HeaderField(name: "etag"),
        HeaderField(name: "if-modified-since"),
        HeaderField(name: "if-none-match"),
        HeaderField(name: "last-modified"),
        HeaderField(name: "link"),
        HeaderField(name: "location"),
        HeaderField(name: "referer"),
        HeaderField(name: "set-cookie"),
        HeaderField(name: ":method", value: "CONNECT"),
        HeaderField(name: ":method", value: "DELETE"),
        HeaderField(name: ":method", value: "GET"),
        HeaderField(name: ":method", value: "HEAD"),
        HeaderField(name: ":method", value: "OPTIONS"),
        HeaderField(name: ":method", value: "POST"),
        HeaderField(name: ":method", value: "PUT"),
        HeaderField(name: ":scheme", value: "http"),
        HeaderField(name: ":scheme", value: "https"),
        HeaderField(name: ":status", value: "103"),
        HeaderField(name: ":status", value: "200"),
        HeaderField(name: ":status", value: "304"),
        HeaderField(name: ":status", value: "404"),
        HeaderField(name: ":status", value: "503"),
        HeaderField(name: "accept", value: "*/*"),
        HeaderField(name: "accept", value: "application/dns-message"),
        HeaderField(name: "accept-encoding", value: "gzip, deflate, br"),
        HeaderField(name: "accept-ranges", value: "bytes"),
        HeaderField(name: "access-control-allow-headers", value: "cache-control"),
        HeaderField(name: "access-control-allow-headers", value: "content-type"),
        HeaderField(name: "access-control-allow-origin", value: "*"),
        HeaderField(name: "cache-control", value: "max-age=0"),
        HeaderField(name: "cache-control", value: "max-age=2592000"),
        HeaderField(name: "cache-control", value: "max-age=604800"),
        HeaderField(name: "cache-control", value: "no-cache"),
        HeaderField(name: "cache-control", value: "no-store"),
        HeaderField(name: "cache-control", value: "public, max-age=31536000"),
        HeaderField(name: "content-encoding", value: "br"),
        HeaderField(name: "content-encoding", value: "gzip"),
        HeaderField(name: "content-type", value: "application/dns-message"),
        HeaderField(name: "content-type", value: "application/javascript"),
        HeaderField(name: "content-type", value: "application/json"),
        HeaderField(name: "content-type", value: "application/x-www-form-urlencoded"),
        HeaderField(name: "content-type", value: "image/gif"),
        HeaderField(name: "content-type", value: "image/jpeg"),
        HeaderField(name: "content-type", value: "image/png"),
        HeaderField(name: "content-type", value: "text/css"),
        HeaderField(name: "content-type", value: "text/html;charset=utf-8"),
        HeaderField(name: "content-type", value: "text/plain"),
        HeaderField(name: "content-type", value: "text/plain;charset=utf-8"),
        HeaderField(name: "range", value: "bytes=0-"),
        HeaderField(name: "strict-transport-security", value: "max-age=31536000"),
        HeaderField(
            name: "strict-transport-security", value: "max-age=31536000;includesubdomains"
        ),
        HeaderField(
            name: "strict-transport-security",
            value: "max-age=31536000;includesubdomains;preload"
        ),
        HeaderField(name: "vary", value: "accept-encoding"),
        HeaderField(name: "vary", value: "origin"),
        HeaderField(name: "x-content-type-options", value: "nosniff"),
        HeaderField(name: "x-xss-protection", value: "1; mode=block"),
        HeaderField(name: ":status", value: "100"),
        HeaderField(name: ":status", value: "204"),
        HeaderField(name: ":status", value: "206"),
        HeaderField(name: ":status", value: "302"),
        HeaderField(name: ":status", value: "400"),
        HeaderField(name: ":status", value: "403"),
        HeaderField(name: ":status", value: "421"),
        HeaderField(name: ":status", value: "425"),
        HeaderField(name: ":status", value: "500"),
        HeaderField(name: "accept-language"),
        HeaderField(name: "access-control-allow-credentials", value: "FALSE"),
        HeaderField(name: "access-control-allow-credentials", value: "TRUE"),
        HeaderField(name: "access-control-allow-headers", value: "*"),
        HeaderField(name: "access-control-allow-methods", value: "get"),
        HeaderField(name: "access-control-allow-methods", value: "get, post, options"),
        HeaderField(name: "access-control-allow-methods", value: "options"),
        HeaderField(name: "access-control-expose-headers", value: "content-length"),
        HeaderField(name: "access-control-request-headers", value: "content-type"),
        HeaderField(name: "access-control-request-method", value: "get"),
        HeaderField(name: "access-control-request-method", value: "post"),
        HeaderField(name: "alt-svc", value: "clear"),
        HeaderField(name: "authorization"),
        HeaderField(
            name: "content-security-policy",
            value: "script-src 'none'; object-src 'none'; base-uri 'none'"
        ),
        HeaderField(name: "early-data", value: "1"),
        HeaderField(name: "expect-ct"),
        HeaderField(name: "forwarded"),
        HeaderField(name: "if-range"),
        HeaderField(name: "origin"),
        HeaderField(name: "purpose", value: "prefetch"),
        HeaderField(name: "server"),
        HeaderField(name: "timing-allow-origin", value: "*"),
        HeaderField(name: "upgrade-insecure-requests", value: "1"),
        HeaderField(name: "user-agent"),
        HeaderField(name: "x-forwarded-for"),
        HeaderField(name: "x-frame-options", value: "deny"),
        HeaderField(name: "x-frame-options", value: "sameorigin")
    ]

    /// Returns the static entry at QPACK index `index` (0...98), or `nil` if out of range.
    public static func field(at index: Int) -> HeaderField? {
        guard index >= 0, index < count else {
            return nil
        }
        return entries[index]
    }

    /// Maps a full `(name, value)` field to its lowest static index, for the encoder's exact-match
    /// lookup (RFC 9204 §4.5.2).
    public static let exactIndex: [HeaderField: Int] = {
        var map = [HeaderField: Int](minimumCapacity: count)
        for (offset, field) in entries.enumerated() where map[field] == nil {
            map[field] = offset
        }
        return map
    }()

    /// Maps a field name to its lowest static index, for the encoder's name-match lookup
    /// (RFC 9204 §4.5.4).
    public static let nameIndex: [String: Int] = {
        var map = [String: Int](minimumCapacity: count)
        for (offset, field) in entries.enumerated() where map[field.name] == nil {
            map[field.name] = offset
        }
        return map
    }()
}
