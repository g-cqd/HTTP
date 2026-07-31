//
//  FileResponderValidatorTests.swift
//  HTTPServerTests
//
//  RFC 9110 §8.8.1 — a *strong* validator promises to change whenever the representation data changes.
//  A validator built from file size and whole-second mtime cannot promise that: §8.8.1 says so outright
//  ("a representation's modification time, if defined with only one-second resolution, might be a weak
//  validator if it is possible for the representation to be modified twice during a single second and
//  retrieved between those modifications"). These tests pin both halves of the fix — the tag is marked
//  weak, and it also carries enough descriptor metadata that two same-size representations stamped to
//  the same second still get different tags.
//

import Foundation
import HTTPCore
import Testing

@testable import HTTPServer

@Suite("FileResponder — cache validators (RFC 9110 §8.8)")
struct FileResponderValidatorTests {
    /// An arbitrary fixed instant both fixtures are stamped to, so their whole-second mtimes collide.
    private static let sharedInstant = Date(timeIntervalSince1970: 1_700_000_000)

    private func get(_ path: String, headers: [(HTTPFieldName, String)] = []) -> HTTPRequest {
        var fields = HTTPFields()
        for (name, value) in headers {
            _ = fields.append(value, for: name)
        }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: path, headerFields: fields
        )
    }

    /// Creates a temp tree, runs `body` against a responder rooted there plus the root URL.
    private func withTree(
        _ files: [String: [UInt8]],
        _ body: (FileResponder, URL) async -> Void
    ) async {
        let manager = FileManager.default
        let root = manager.temporaryDirectory
            .appendingPathComponent("filevalidator-\(UUID().uuidString)")
        try? manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }
        for (name, bytes) in files {
            manager.createFile(atPath: root.path + "/" + name, contents: Data(bytes))
        }
        await body(FileResponder(root: root.path), root)
    }

    /// The `ETag` the responder sends for `path`.
    private func etag(_ responder: FileResponder, _ path: String) async -> String {
        await responder.respond(to: get(path), body: []).head.headerFields[.etag] ?? ""
    }

    /// Stamps `name` under `root` to ``sharedInstant``, collapsing any sub-second difference.
    private func stamp(_ name: String, in root: URL) {
        try? FileManager.default.setAttributes(
            [.modificationDate: Self.sharedInstant], ofItemAtPath: root.path + "/" + name
        )
    }

    @Test("a metadata-only validator is marked weak (RFC 9110 §8.8.1)")
    func validatorIsWeak() async {
        await withTree(["a.txt": Array("hello".utf8)]) { responder, _ in
            #expect(await etag(responder, "/a.txt").hasPrefix("W/\""))
        }
    }

    @Test("two same-size files stamped to the same second do not share a validator")
    func sameSizeSameSecondDoNotCollide() async {
        // Identical length, different bytes — the exact shape the finding describes.
        let files = ["a.txt": Array("AAAA".utf8), "b.txt": Array("BBBB".utf8)]
        await withTree(files) { responder, root in
            stamp("a.txt", in: root)
            stamp("b.txt", in: root)
            let first = await etag(responder, "/a.txt")
            let second = await etag(responder, "/b.txt")
            #expect(!first.isEmpty)
            #expect(first != second, "same-size, same-second files shared the tag \(first)")
        }
    }

    @Test("a same-size in-place rewrite within one second never reuses a strong validator")
    func inPlaceRewriteWithinOneSecond() async {
        await withTree(["a.txt": Array("AAAA".utf8)]) { responder, root in
            let before = await etag(responder, "/a.txt")
            try? Data("BBBB".utf8).write(to: root.appendingPathComponent("a.txt"))
            let after = await etag(responder, "/a.txt")
            // Either the tag moved, or it never claimed to be strong. Both are RFC 9110 §8.8.1
            // conformant; the second is what a metadata-only validator can actually guarantee on a
            // filesystem whose timestamps have no sub-second component.
            #expect(after != before || before.hasPrefix("W/"))
            #expect(before.hasPrefix("W/") && after.hasPrefix("W/"))
        }
    }

    @Test("the weak validator still round-trips If-None-Match to a 304 (RFC 9110 §13.1.2)")
    func weakTagStillCollapsesTo304() async {
        await withTree(["a.txt": Array("cacheme".utf8)]) { responder, _ in
            let tag = await etag(responder, "/a.txt")
            let request = get("/a.txt", headers: [(.ifNoneMatch, tag)])
            let response = await responder.respond(to: request, body: [])
            #expect(response.head.status == .notModified)
            #expect(response.head.headerFields[.etag] == tag)
        }
    }

    @Test("a precompressed representation gets its own validator, not the identity one")
    func precompressedTagDiffers() async {
        let files = ["a.css": Array("body{}".utf8), "a.css.br": Array("BROTL".utf8)]
        await withTree(files) { responder, root in
            stamp("a.css", in: root)
            stamp("a.css.br", in: root)
            let identity = await etag(responder, "/a.css")
            let request = get("/a.css", headers: [(.acceptEncoding, "br")])
            let response = await responder.respond(to: request, body: [])
            let coded = response.head.headerFields[.etag] ?? ""
            #expect(identity != coded)
            #expect(coded.hasSuffix("-br\""))
            #expect(coded.hasPrefix("W/\""))
        }
    }
}
