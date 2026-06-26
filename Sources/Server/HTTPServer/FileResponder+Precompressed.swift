//
//  FileResponder+Precompressed.swift
//  HTTPServer
//
//  RFC 9110 §8.4.1 / §12.5.3 — precompressed sidecar negotiation for ``FileResponder``. When the client
//  accepts `br`/`gzip` and a `<file>.br`/`.gz` sibling exists, is jailed inside the root, and is no older
//  than the original (a stale sidecar is never served), serve it with `Content-Encoding` + `Vary`. A
//  `Range` request always serves the identity bytes — a range over the compressed stream is not offered.
//

internal import Foundation
internal import HTTPCore

extension FileResponder {
    /// Media-type fragments whose payloads are already compressed — no precompressed sibling is sought.
    private static let incompressibleTypes = [
        "image/", "video/", "audio/", "zip", "gzip", "brotli", "compress", "octet-stream"
    ]

    /// The fresh, accepted precompressed sibling of `path` to serve (with its content coding), or nil to
    /// serve the identity file.
    func precompressedChoice(
        _ path: String,
        request: HTTPRequest
    ) -> (path: String, encoding: String)? {
        guard request.headerFields[.range] == nil, Self.isCompressible(path) else {
            return nil
        }
        guard case .file(_, let originalModified) = Self.classify(path) else {
            return nil
        }
        let accept = request.headerFields[.acceptEncoding] ?? ""
        for (token, suffix) in [("br", ".br"), ("gzip", ".gz")] where Self.accepts(accept, token) {
            guard let sidecar = inRoot(path + suffix),
                case .file(_, let sidecarModified) = Self.classify(sidecar),
                sidecarModified >= originalModified  // never serve a stale sidecar
            else {
                continue
            }
            return (sidecar, token)
        }
        return nil
    }

    /// Whether to seek a precompressed sibling for `path`, skipping already-compressed media types.
    private static func isCompressible(_ path: String) -> Bool {
        let type = contentType(path).lowercased()
        return !incompressibleTypes.contains { type.contains($0) }
    }

    /// Whether `acceptEncoding` offers `token` (present and not `;q=0`) (RFC 9110 §12.5.3).
    private static func accepts(_ acceptEncoding: String, _ token: String) -> Bool {
        for part in acceptEncoding.lowercased().split(separator: ",") {
            let fields = part.split(separator: ";")
            let coding = fields.first?.trimmingCharacters(in: .whitespaces) ?? ""
            guard coding == token || coding == "*" else {
                continue
            }
            let refused = fields.dropFirst()
                .contains {
                    $0.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " ", with: "")
                        == "q=0"
                }
            if !refused {
                return true
            }
        }
        return false
    }
}
