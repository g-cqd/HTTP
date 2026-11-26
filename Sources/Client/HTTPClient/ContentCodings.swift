//
//  ContentCodings.swift
//  HTTPClient
//
//  RFC 9110 §8.4 — removes the `Content-Encoding` codings a response was sent with, last-applied
//  first, under a decompressed-size bound (CWE-409) and a layer cap: `zstd` (RFC 8878, HTTPZstd),
//  `gzip` / `x-gzip` (RFC 1952) and `deflate` (RFC 1950, with the bare-RFC-1951 fallback real
//  servers send), all through the in-house, fail-closed decoders.
//

internal import HTTPDeflate
internal import HTTPZstd

/// Decodes RFC 9110 §8.4 content codings.
enum ContentCodings {
    /// The `Accept-Encoding` value advertised when automatic decompression is on.
    static let acceptEncoding = "zstd, gzip, deflate"
    /// The most stacked codings decoded (RFC 9110 allows a list; real servers send one).
    static let maxLayers = 2

    /// Splits a comma-separated field value into lowercased, OWS-trimmed tokens (RFC 9110 §5.6.1).
    static func tokens(_ value: String) -> [String] {
        value.split(separator: ",")
            .compactMap { part in
                let token = trimmingOWS(part).lowercased()
                return token.isEmpty ? nil : token
            }
    }

    /// Drops leading and trailing optional whitespace (SP / HTAB, RFC 9110 §5.6.3).
    private static func trimmingOWS(_ part: Substring) -> String {
        let isOWS: (Character) -> Bool = { $0 == " " || $0 == "\t" }
        guard let first = part.firstIndex(where: { !isOWS($0) }),
            let last = part.lastIndex(where: { !isOWS($0) })
        else {
            return ""
        }
        return String(part[first ... last])
    }

    /// Removes every coding in `encodings` (in reverse application order) from `body`.
    static func decode(
        _ body: [UInt8], encodings: [String], maxOutput: Int
    ) throws(HTTPClientError) -> [UInt8] {
        let layers = encodings.flatMap(tokens).filter { $0 != "identity" }
        guard !layers.isEmpty else {
            return body
        }
        guard layers.count <= maxLayers else {
            throw .undecodableBody("too many content codings (\(layers.count))")
        }
        var current = body
        for coding in layers.reversed() where !current.isEmpty {
            current = try decodeLayer(current, coding: coding, maxOutput: maxOutput)
        }
        return current
    }

    private static func decodeLayer(
        _ input: [UInt8],
        coding: String,
        maxOutput: Int
    ) throws(HTTPClientError) -> [UInt8] {
        switch coding {
            case "zstd":
                do {
                    return try Zstd.decompress(input, maxOutputSize: maxOutput)
                }
                catch {
                    throw .undecodableBody("zstd: \(error)")
                }
            case "gzip", "x-gzip":
                return try inflate(input, formats: [.gzip], maxOutput: maxOutput)
            case "deflate":
                return try inflate(input, formats: [.zlib, .raw], maxOutput: maxOutput)
            default:
                throw .undecodableBody("unsupported content coding \(coding)")
        }
    }

    /// One-shot inflate under geometric destination growth, failing closed at `maxOutput`.
    private static func inflate(
        _ input: [UInt8],
        formats: [DeflateCodec.Format],
        maxOutput: Int
    ) throws(HTTPClientError) -> [UInt8] {
        for format in formats {
            var capacity = min(max(input.count * 4, 64 * 1_024), maxOutput)
            while true {
                if let output = DeflateCodec.decompress(input, format: format, capacity: capacity) {
                    return output
                }
                guard capacity < maxOutput else {
                    break
                }
                capacity = capacity <= maxOutput / 2 ? capacity * 2 : maxOutput
            }
        }
        throw .undecodableBody("deflate stream malformed or larger than \(maxOutput) octets")
    }
}
