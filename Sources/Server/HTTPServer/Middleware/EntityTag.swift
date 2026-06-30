//
//  EntityTag.swift
//  HTTPServer
//
//  RFC 9110 §8.8.3 — a body-derived entity-tag, shared by the conditional-request, Range, and static-file
//  layers so all compute and compare the *same* validator (a client's `If-Range`/`If-None-Match` tag,
//  minted from an earlier response, must match regardless of which layer checks it). The tag is
//  `"<hex size>-<hex CRC-32>"`: a collision needs the same length *and* CRC-32, strong enough for a cache
//  validator and needs no crypto. This type also centralizes the §13.1 tag-comparison rules so the
//  conditional middleware and the file responder share one implementation.
//

internal import Foundation
internal import HTTPCore

/// Derives and compares strong entity-tags for representation bodies (RFC 9110 §8.8.3 / §13.1).
enum EntityTag {
    /// The strong entity-tag for `body`: `"<hex size>-<hex CRC-32>"`.
    static func crc(for body: [UInt8]) -> String {
        "\"\(String(body.count, radix: 16))-\(String(CRC32.checksum(body), radix: 16))\""
    }

    /// An entity-tag's opaque value — the tag with any weak `W/` prefix removed (RFC 9110 §8.8.3).
    static func opaque(_ tag: some StringProtocol) -> String {
        tag.hasPrefix("W/") ? String(tag.dropFirst(2)) : String(tag)
    }

    /// Whether any entry across `candidates` (comma-separated `If-None-Match` field values) matches
    /// `etag` under weak comparison (RFC 9110 §13.1.2); `*` matches any current representation.
    static func weakMatches(_ candidates: [String], _ etag: String) -> Bool {
        let target = opaque(etag)
        for value in candidates {
            for element in value.split(separator: ",") {
                let candidate = element.trimmingCharacters(in: .whitespaces)
                if candidate == "*" || opaque(candidate) == target {
                    return true
                }
            }
        }
        return false
    }

    /// Whether any entry across `candidates` (comma-separated `If-Match` field values) matches `etag`
    /// under strong comparison (RFC 9110 §13.1.1) — a weak (`W/`) tag never matches; `*` matches any
    /// current representation.
    static func strongMatches(_ candidates: [String], _ etag: String) -> Bool {
        guard !etag.hasPrefix("W/") else {
            return false
        }
        for value in candidates {
            for element in value.split(separator: ",") {
                let candidate = element.trimmingCharacters(in: .whitespaces)
                if candidate == "*" || (!candidate.hasPrefix("W/") && candidate == etag) {
                    return true
                }
            }
        }
        return false
    }
}
