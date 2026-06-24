//
//  HTTPVersion+CustomStringConvertible.swift
//  HTTP1
//
//  RFC 9112 §2.3 — the wire rendering of an HTTP version token (extracted from HTTPVersion.swift so
//  the conformance lives in its own file rather than a same-file grouping extension).
//

extension HTTPVersion: CustomStringConvertible {
    /// The wire form, e.g. `"HTTP/1.1"`.
    public var description: String {
        "HTTP/\(major).\(minor)"
    }
}
