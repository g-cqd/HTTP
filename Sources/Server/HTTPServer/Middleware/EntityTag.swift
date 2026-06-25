//
//  EntityTag.swift
//  HTTPServer
//
//  RFC 9110 §8.8.3 — a body-derived entity-tag, shared by the conditional-request and Range layers so
//  both compute the *same* validator (a client's `If-Range`/`If-None-Match` tag, minted from an earlier
//  response, must match regardless of which layer checks it). The tag is `"<hex size>-<hex CRC-32>"`: a
//  collision needs the same length *and* CRC-32, strong enough for a cache validator and needs no crypto.
//

internal import HTTPCore

/// Derives a strong entity-tag from a representation body (RFC 9110 §8.8.3).
enum EntityTag {
    /// The strong entity-tag for `body`: `"<hex size>-<hex CRC-32>"`.
    static func crc(for body: [UInt8]) -> String {
        "\"\(String(body.count, radix: 16))-\(String(CRC32.checksum(body), radix: 16))\""
    }
}
