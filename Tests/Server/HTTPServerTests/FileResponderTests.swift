//
//  FileResponderTests.swift
//  HTTPServerTests
//
//  Static file serving (RFC 9110): serving a file with content-type and validators, 404 for a missing
//  file, 403 for a traversal path (CWE-22) or a symlink component (CWE-59), HEAD with Content-Length and
//  no body, byte ranges (206), the If-None-Match → 304 collapse, index.html for the root, and streaming a
//  large file. Each test runs against a throwaway temp directory. The TOCTOU regressions for the
//  descriptor-anchored resolution live in `FileResponderSymlinkRaceTests` and `RootDirectoryTests`.
//

import Foundation
import HTTPCore
import Testing

@testable import HTTPServer

@Suite("FileResponder — static files (RFC 9110)")
struct FileResponderTests {
    /// Creates a temp directory containing `files`, runs `body` against a responder rooted there, and
    /// removes the directory afterward.
    private func withRoot(
        _ files: [String: [UInt8]],
        streamingThreshold: Int = 1 << 20,
        _ body: (FileResponder) async -> Void
    ) async {
        let manager = FileManager.default
        let root = manager.temporaryDirectory
            .appendingPathComponent("fileresponder-\(UUID().uuidString)")
        try? manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }
        FileTree.write(files, into: root)
        await body(FileResponder(root: root.path, streamingThreshold: streamingThreshold))
    }

    private func get(
        _ path: String,
        method: HTTPMethod = .get,
        headers: [(HTTPFieldName, String)] = []
    ) -> HTTPRequest {
        var fields = HTTPFields()
        for (name, value) in headers {
            _ = fields.append(value, for: name)
        }
        return HTTPRequest(
            method: method, scheme: "https", authority: "x", path: path, headerFields: fields
        )
    }

    @Test("serves a file with content-type and validators")
    func servesFile() async {
        await withRoot(["hello.txt": Array("hello world".utf8)]) { responder in
            let response = await responder.respond(to: get("/hello.txt"), body: [])
            #expect(response.head.status == .ok)
            #expect(response.body == Array("hello world".utf8))
            #expect(response.head.headerFields[.contentType] == "text/plain; charset=utf-8")
            #expect(response.head.headerFields[.etag] != nil)
            #expect(response.head.headerFields[.lastModified] != nil)
            #expect(response.head.headerFields[.acceptRanges] == "bytes")
        }
    }

    @Test("a missing file is 404")
    func missing() async {
        await withRoot([:]) { responder in
            let response = await responder.respond(to: get("/nope.txt"), body: [])
            #expect(response.head.status == .notFound)
        }
    }

    @Test("a traversal path is rejected with 403 (CWE-22)")
    func traversal() async {
        await withRoot(["secret.txt": Array("x".utf8)]) { responder in
            let response = await responder.respond(to: get("/../../../etc/passwd"), body: [])
            #expect(response.head.status == .forbidden)
        }
    }

    @Test("a symlink inside the root pointing outside it is rejected (CWE-22 symlink escape)")
    func symlinkEscape() async {
        let manager = FileManager.default
        let base = manager.temporaryDirectory
            .appendingPathComponent("fileresponder-symlink-\(UUID().uuidString)")
        let root = base.appendingPathComponent("docroot")
        let outside = base.appendingPathComponent("secret")
        try? manager.createDirectory(at: root, withIntermediateDirectories: true)
        try? manager.createDirectory(at: outside, withIntermediateDirectories: true)
        _ = manager.createFile(
            atPath: outside.appendingPathComponent("passwd").path, contents: Data("TOP SECRET".utf8)
        )
        _ = manager.createFile(
            atPath: root.appendingPathComponent("ok.txt").path, contents: Data("ok".utf8)
        )
        // A symlink inside the docroot pointing to the sibling secret dir — no `..` appears in the URL.
        try? manager.createSymbolicLink(
            at: root.appendingPathComponent("link"), withDestinationURL: outside
        )
        defer { try? manager.removeItem(at: base) }

        let responder = FileResponder(root: root.path)
        // A genuine in-root file still serves — symlink resolution must not over-reject.
        let inside = await responder.respond(to: get("/ok.txt"), body: [])
        #expect(inside.head.status == .ok)
        // The symlink escape is refused.
        let escape = await responder.respond(to: get("/link/passwd"), body: [])
        #expect(escape.head.status == .forbidden)
        #expect(escape.body.isEmpty)
    }

    @Test("a file the process cannot open is refused with 403, with no body")
    func unopenableFileRefused() async {
        // Root bypasses POSIX permissions, so the unreadable case cannot be staged there.
        if getuid() == 0 {
            return
        }
        await withTree(["locked.txt": Array("secret".utf8)]) { responder, root in
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0], ofItemAtPath: root.path + "/locked.txt"
            )
            // Resolution *is* the open now, so `EACCES` surfaces here as a 403 rather than as a 500 from
            // a later read: there is no longer a window in which a stat succeeds and the open then fails.
            let response = await responder.respond(to: get("/locked.txt"), body: [])
            #expect(response.head.status == .forbidden)
            #expect(response.body.isEmpty)
        }
    }

    @Test("a file truncated after the head is framed fails the stream, never ships a short body")
    func truncatedStreamFailsClosed() async {
        let big = [UInt8](repeating: 0x41, count: 4_096)
        await withTree(["big.bin": big], streamingThreshold: 1_024) { responder, root in
            let response = await responder.respond(to: get("/big.bin"), body: [])
            #expect(response.head.headerFields[.contentLength] == "4096")
            // The Content-Length is committed; the file now cannot honour it.
            #expect(truncate(root.path + "/big.bin", 16) == 0)
            #expect(await response.stream?.collect(maxBytes: 1 << 20) == nil)
        }
    }

    @Test("HEAD sends Content-Length but no body (RFC 9112 §6.3)")
    func head() async {
        await withRoot(["a.txt": Array("0123456789".utf8)]) { responder in
            let response = await responder.respond(to: get("/a.txt", method: .head), body: [])
            #expect(response.head.status == .ok)
            #expect(response.head.headerFields[.contentLength] == "10")
            #expect(response.body.isEmpty)
        }
    }

    @Test("a byte range returns 206 Partial Content with the sliced body (RFC 9110 §14)")
    func range() async {
        await withRoot(["a.txt": Array("0123456789".utf8)]) { responder in
            let request = get("/a.txt", headers: [(.range, "bytes=2-5")])
            let response = await responder.respond(to: request, body: [])
            #expect(response.head.status == .partialContent)
            #expect(response.head.headerFields[.contentRange] == "bytes 2-5/10")
            #expect(response.body == Array("2345".utf8))
        }
    }

    @Test("a matching If-None-Match collapses to 304 (RFC 9110 §13.1.2)")
    func notModified() async {
        await withRoot(["a.txt": Array("cacheme".utf8)]) { responder in
            let first = await responder.respond(to: get("/a.txt"), body: [])
            let etag = first.head.headerFields[.etag] ?? ""
            let request = get("/a.txt", headers: [(.ifNoneMatch, etag)])
            let response = await responder.respond(to: request, body: [])
            #expect(response.head.status == .notModified)
            #expect(response.body.isEmpty)
        }
    }

    @Test("index.html is served for the root path")
    func indexForRoot() async {
        await withRoot(["index.html": Array("<h1>home</h1>".utf8)]) { responder in
            let response = await responder.respond(to: get("/"), body: [])
            #expect(response.head.status == .ok)
            #expect(response.body == Array("<h1>home</h1>".utf8))
            #expect(response.head.headerFields[.contentType] == "text/html; charset=utf-8")
        }
    }

    @Test("a file larger than the threshold is streamed, not buffered")
    func streamsLargeFile() async {
        let big = [UInt8](repeating: 0x41, count: 4_096)
        await withRoot(["big.bin": big], streamingThreshold: 1_024) { responder in
            let response = await responder.respond(to: get("/big.bin"), body: [])
            #expect(response.stream != nil)  // 4096 > the 1024 threshold
            #expect(response.head.headerFields[.contentLength] == "4096")
            #expect(await response.stream?.collect(maxBytes: 1 << 20) == big)
        }
    }

    // MARK: G5 — precompressed sidecars, try_files, autoindex

    @Test("serves a fresh precompressed .br sidecar when the client accepts it (RFC 9110 §12.5.3)")
    func precompressedSidecar() async {
        let identity = Array("body { color: red }".utf8)
        let sidecar = Array("OPAQUE-BROTLI".utf8)  // the bytes are opaque to the responder
        await withTree(["app.css": identity, "app.css.br": sidecar]) { responder, _ in
            let request = get("/app.css", headers: [(.acceptEncoding, "br")])
            let response = await responder.respond(to: request, body: [])
            #expect(response.head.status == .ok)
            #expect(response.head.headerFields[.contentEncoding] == "br")
            #expect(response.head.headerFields[.vary]?.contains("Accept-Encoding") == true)
            #expect(response.body == sidecar)
            #expect(response.head.headerFields[.contentType] == "text/css; charset=utf-8")
            #expect(response.head.headerFields[.etag]?.contains("-br") == true)
        }
    }

    @Test("a stale precompressed sidecar (older than the original) is not served")
    func staleSidecarSkipped() async {
        let identity = Array("html { }".utf8)
        await withTree(["a.css": identity, "a.css.br": Array("OLD".utf8)]) { responder, root in
            let future = Date().addingTimeInterval(120)  // make the original newer than the sidecar
            try? FileManager.default.setAttributes(
                [.modificationDate: future], ofItemAtPath: root.path + "/a.css"
            )
            let request = get("/a.css", headers: [(.acceptEncoding, "br")])
            let response = await responder.respond(to: request, body: [])
            #expect(response.head.headerFields[.contentEncoding] == nil)
            #expect(response.body == identity)
        }
    }

    @Test("one whole second of staleness is enough — the granularity, not just the direction")
    func oneSecondOlderSidecarIsStale() async {
        // `FileResponder+Precompressed.sidecar` compares `st_mtimespec.tv_sec`: WHOLE SECONDS, with the
        // nanosecond field deliberately unused. `staleSidecarSkipped` above shows the *direction* with a
        // two-minute gap; this shows the *granularity*, which is the load-bearing part — one tick of the
        // clock between writing a sidecar and writing its identity file is enough to make the sidecar
        // stale. That is precisely why the test trees are now written in sorted key order (`FileTree`):
        // with dictionary order a sidecar could be written first, and a scheduling stall across a second
        // boundary then turned every negotiated assertion in the suite into a rare, unexplained failure.
        let identity = Array("html { }".utf8)
        await withTree(["a.css": identity, "a.css.br": Array("OLD".utf8)]) { responder, root in
            let attributes = try? FileManager.default.attributesOfItem(
                atPath: root.path + "/a.css"
            )
            guard let written = attributes?[.modificationDate] as? Date else {
                Issue.record("the identity file has no modification date")
                return
            }
            try? FileManager.default.setAttributes(
                [.modificationDate: written.addingTimeInterval(-1)],
                ofItemAtPath: root.path + "/a.css.br"
            )
            let request = get("/a.css", headers: [(.acceptEncoding, "br")])
            let response = await responder.respond(to: request, body: [])
            #expect(response.head.headerFields[.contentEncoding] == nil)
            #expect(response.body == identity)
        }
    }

    @Test("a Range request serves identity bytes, never the precompressed sidecar")
    func rangeIgnoresSidecar() async {
        await withTree(["a.css": Array("0123456789".utf8), "a.css.br": Array("BR".utf8)]) {
            responder, _ in
            let request = get("/a.css", headers: [(.acceptEncoding, "br"), (.range, "bytes=0-3")])
            let response = await responder.respond(to: request, body: [])
            #expect(response.head.status == .partialContent)
            #expect(response.head.headerFields[.contentEncoding] == nil)
            #expect(response.body == Array("0123".utf8))
        }
    }

    @Test("try_files serves the fallback for a missing path (SPA routing)")
    func tryFilesFallback() async {
        let app = Array("<div id=app></div>".utf8)
        await withTree(["index.html": app], fallback: "index.html") { responder, _ in
            let response = await responder.respond(to: get("/app/deep/route"), body: [])
            #expect(response.head.status == .ok)
            #expect(response.body == app)
            #expect(response.head.headerFields[.contentType] == "text/html; charset=utf-8")
        }
    }

    @Test("autoindex is off by default — a directory without index.html is 404")
    func autoindexOffByDefault() async {
        await withTree(["a.txt": Array("x".utf8)]) { responder, _ in
            let response = await responder.respond(to: get("/"), body: [])
            #expect(response.head.status == .notFound)
        }
    }

    @Test("autoindex lists entries and HTML-escapes names (XSS-safe) when enabled")
    func autoindexListsAndEscapes() async {
        let files = ["a&b<c.txt": Array("x".utf8), "plain.txt": Array("y".utf8)]
        await withTree(files, autoindex: true) { responder, _ in
            let response = await responder.respond(to: get("/"), body: [])
            #expect(response.head.status == .ok)
            #expect(response.head.headerFields[.contentType] == "text/html; charset=utf-8")
            let html = String(bytes: response.body, encoding: .utf8) ?? ""
            #expect(html.contains("a&amp;b&lt;c.txt"))  // escaped
            #expect(!html.contains("a&b<c.txt"))  // never the raw, unescaped name
            #expect(html.contains("plain.txt"))
        }
    }

    /// Creates a temp tree, runs `body` against a responder rooted there (with the given options) plus the
    /// root URL (for mtime tweaks), and removes the tree afterward.
    private func withTree(
        _ files: [String: [UInt8]],
        streamingThreshold: Int = 1 << 20,
        precompressed: Bool = true,
        autoindex: Bool = false,
        fallback: String? = nil,
        _ body: (FileResponder, URL) async -> Void
    ) async {
        let manager = FileManager.default
        let root = manager.temporaryDirectory
            .appendingPathComponent("fileresponder-\(UUID().uuidString)")
        try? manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }
        FileTree.write(files, into: root)
        let responder = FileResponder(
            root: root.path,
            streamingThreshold: streamingThreshold,
            precompressed: precompressed,
            autoindex: autoindex,
            fallback: fallback
        )
        await body(responder, root)
    }
}
