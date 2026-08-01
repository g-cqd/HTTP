//
//  OneShotOnlyEncoder.swift
//  HTTPServerTests
//
//  A plain ``ContentEncoder`` — the shape every consumer-supplied encoder had before the streaming seam
//  existed, and the shape `CZstd`/`CZlibCoding`/`CBrotli` still have. It must keep working for buffered
//  responses and must leave a *streamed* response uncoded rather than being buffered to code it.
//
//  A distinct type rather than a mode of ``ProbeContentEncoder`` because the thing under test is the
//  absence of a conformance, which cannot be an instance property.
//

@testable import HTTPServer

/// A content coding with no incremental form at all.
struct OneShotOnlyEncoder: ContentEncoder {
    /// The `Content-Encoding` token this fixture claims.
    let token: String

    func encode(_ body: [UInt8]) -> [UInt8]? {
        guard !body.isEmpty else {
            return nil
        }
        return ProbeContentEncoder.coded(body, from: 0)
    }
}
