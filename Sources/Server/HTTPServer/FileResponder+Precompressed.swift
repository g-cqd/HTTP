//
//  FileResponder+Precompressed.swift
//  HTTPServer
//
//  RFC 9110 §8.4.1 / §12.5.3 — precompressed sidecar negotiation for ``FileResponder``. When the client
//  accepts `br`/`gzip` and a `<file>.br`/`.gz` sibling exists and is no older than the original (a stale
//  sidecar is never served), serve it with `Content-Encoding` + `Vary`. A `Range` request always serves
//  the identity bytes — a range over the compressed stream is not offered.
//
//  Which coding wins is decided by ``AcceptEncoding``, which parses the header ONCE into quality values;
//  this file only turns that ranking into `openat(2)` attempts. Brotli has no hardcoded precedence — it
//  wins a tie, and loses `br;q=0.1, gzip;q=0.9`.
//
//  The sidecar is opened with `openat(2)` on the SAME directory descriptor that reached the identity
//  file, so it is inside the root by construction and no pathname is rebuilt or re-resolved; a symlinked
//  sidecar is refused like any other symlink (CWE-59, CWE-367).
//

internal import Foundation
internal import HTTPCore

extension FileResponder {
    /// Media-type fragments whose payloads are already compressed — no precompressed sibling is sought.
    private static let incompressibleTypes = [
        "image/", "video/", "audio/", "zip", "gzip", "brotli", "compress", "octet-stream"
    ]

    /// The fresh, accepted precompressed sibling of `file` to serve (with its content coding), or nil to
    /// serve the identity file.
    ///
    /// At most two `openat(2)` attempts, in the client's own order of preference, stopping at the first
    /// sidecar that exists and is not stale.
    func precompressedChoice(
        _ file: OpenedFile,
        named name: Substring,
        in directory: OpenedDirectory,
        accept: AcceptEncoding
    ) -> (file: OpenedFile, encoding: String)? {
        let candidates = accept.candidates
        if let first = candidates.first,
            let choice = Self.sidecar(first, freshFor: file, named: name, in: directory)
        {
            return choice
        }
        guard let second = candidates.second else {
            return nil
        }
        return Self.sidecar(second, freshFor: file, named: name, in: directory)
    }

    /// The `<name><suffix>` sibling for `coding`, or nil when it is missing or older than `file`.
    private static func sidecar(
        _ coding: AcceptEncoding.Coding,
        freshFor file: OpenedFile,
        named name: Substring,
        in directory: OpenedDirectory
    ) -> (file: OpenedFile, encoding: String)? {
        guard let sidecar = directory.openFile(named: name + coding.suffix),
            sidecar.modifiedAt >= file.modifiedAt  // never serve a stale sidecar
        else {
            return nil
        }
        return (sidecar, coding.rawValue)
    }

    /// Whether to seek a precompressed sibling for `name`, skipping already-compressed media types.
    ///
    /// This is also what decides `Vary: Accept-Encoding`: a resource no sidecar will ever be sought
    /// for is not negotiated, and claiming otherwise only fragments every downstream cache key.
    static func isCompressible(_ name: Substring) -> Bool {
        let type = contentType(name).lowercased()
        return !incompressibleTypes.contains { type.contains($0) }
    }
}
