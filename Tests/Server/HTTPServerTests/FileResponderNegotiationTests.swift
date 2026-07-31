//
//  FileResponderNegotiationTests.swift
//  HTTPServerTests
//
//  RFC 9110 §12.5.5 / §15.4.5 — `Vary` tells a cache which request headers select the representation,
//  so it must be identical on the `304` and on the `200` it revalidates. A cache that stored the 200
//  under `Vary: Accept-Encoding` and is then handed a `Vary`-less `304` has been told the resource is
//  no longer negotiated, and may hand the stored Brotli bytes to a client that never asked for them
//  (§15.4.5 lists `Vary` among the fields a 304 MUST carry when the 200 would have).
//

import Foundation
import HTTPCore
import Testing

@testable import HTTPServer

@Suite("FileResponder — content negotiation invariants (RFC 9110 §12.5)")
struct FileResponderNegotiationTests {
    private func get(_ path: String, headers: [(HTTPFieldName, String)] = []) -> HTTPRequest {
        var fields = HTTPFields()
        for (name, value) in headers {
            _ = fields.append(value, for: name)
        }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: path, headerFields: fields
        )
    }

    /// Creates a temp tree and runs `body` against a responder rooted there.
    private func withTree(
        _ files: [String: [UInt8]],
        precompressed: Bool = true,
        _ body: (FileResponder) async -> Void
    ) async {
        let manager = FileManager.default
        let root = manager.temporaryDirectory
            .appendingPathComponent("filenegotiation-\(UUID().uuidString)")
        try? manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }
        for (name, bytes) in files {
            manager.createFile(atPath: root.path + "/" + name, contents: Data(bytes))
        }
        await body(FileResponder(root: root.path, precompressed: precompressed))
    }

    /// The 200 for `path` under `accept`, then the 304 its own `ETag` revalidates into.
    private func pair(
        _ responder: FileResponder,
        _ path: String,
        accept: String
    ) async -> (ok: ServerResponse, notModified: ServerResponse) {
        let headers = [(HTTPFieldName.acceptEncoding, accept)]
        let ok = await responder.respond(to: get(path, headers: headers), body: [])
        let tag = ok.head.headerFields[.etag] ?? ""
        let revalidate = get(path, headers: headers + [(.ifNoneMatch, tag)])
        return (ok, await responder.respond(to: revalidate, body: []))
    }

    @Test(
        "a precompressed 304 carries the same Vary as its 200 (RFC 9110 §15.4.5)",
        arguments: ["br", "gzip", "identity", ""]
    )
    func varyIsInvariantAcrossStatuses(_ accept: String) async {
        let files = ["a.css": Array("body{}".utf8), "a.css.br": Array("BR".utf8)]
        await withTree(files) { responder in
            let both = await pair(responder, "/a.css", accept: accept)
            #expect(both.ok.head.status == .ok)
            #expect(both.notModified.head.status == .notModified)
            #expect(
                both.notModified.head.headerFields.values(for: .vary)
                    == both.ok.head.headerFields.values(for: .vary))
            #expect(both.ok.head.headerFields[.vary]?.contains("Accept-Encoding") == true)
        }
    }

    @Test("the 200 advertises Vary even when this request got no sidecar")
    func varyAdvertisedWithoutASidecar() async {
        // No sidecar exists at all, but the resource is still negotiated: a cache that stores this
        // identity copy without `Vary` would replay it to a Brotli-capable client once one appears.
        await withTree(["a.css": Array("body{}".utf8)]) { responder in
            let response = await responder.respond(to: get("/a.css"), body: [])
            #expect(response.head.headerFields[.vary]?.contains("Accept-Encoding") == true)
            #expect(response.head.headerFields[.contentEncoding] == nil)
        }
    }

    @Test("a resource that is never negotiated advertises no Vary")
    func noVaryWhenNotNegotiated() async {
        // Precompression disabled: the representation cannot vary, so claiming it does would only
        // fragment every downstream cache key for nothing.
        await withTree(["a.css": Array("body{}".utf8)], precompressed: false) { responder in
            let response = await responder.respond(to: get("/a.css"), body: [])
            #expect(response.head.headerFields[.vary] == nil)
        }
        // An already-compressed media type is never given a sidecar either.
        await withTree(["a.png": Array("PNG".utf8)]) { responder in
            let response = await responder.respond(to: get("/a.png"), body: [])
            #expect(response.head.headerFields[.vary] == nil)
        }
    }

    @Test("the 304 keeps ETag and Last-Modified alongside Vary (RFC 9110 §15.4.5)")
    func notModifiedCarriesTheValidators() async {
        let files = ["a.css": Array("body{}".utf8), "a.css.br": Array("BR".utf8)]
        await withTree(files) { responder in
            let both = await pair(responder, "/a.css", accept: "br")
            let head = both.notModified.head
            #expect(head.headerFields[.etag] == both.ok.head.headerFields[.etag])
            #expect(head.headerFields[.lastModified] == both.ok.head.headerFields[.lastModified])
            #expect(both.notModified.body.isEmpty)
        }
    }
}
