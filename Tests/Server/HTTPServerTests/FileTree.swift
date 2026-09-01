//
//  FileTree.swift
//  HTTPServerTests
//
//  Writes a static-file test tree in an order that cannot make a sidecar look stale.
//
//  Every `FileResponder` suite built its tree by iterating a `[String: [UInt8]]` — and Swift randomizes
//  Dictionary iteration order per process. That is a latent, load-sensitive flake, because
//  `FileResponder+Precompressed.sidecar` refuses a sidecar older than the file it accompanies
//  (`sidecar.modifiedAt >= file.modifiedAt`, "never serve a stale sidecar") and `modifiedAt` is
//  `st_mtimespec.tv_sec` — WHOLE SECONDS. So if a run happens to create `a.css.br` before `a.css`, and
//  the scheduler puts a stall between the two `createFile` calls that crosses a second boundary, the
//  sidecar is a second older than the identity file, is judged stale, and every test expecting a
//  negotiated `Content-Encoding` fails. Microseconds apart it essentially never happens; under a loaded
//  `swift test --parallel` it eventually does, once, unreproducibly.
//
//  The production rule is correct and deliberate (`FileResponderTests.staleSidecarSkipped` pins it, and
//  nginx's `gzip_static` behaves the same way) — the harness was the part relying on luck. Writing in
//  sorted key order removes the luck: a sidecar's name is its base name plus a suffix, so the base
//  always sorts strictly before it and `mtime` is non-decreasing in creation order. Whatever the second
//  boundary does, `sidecar.modifiedAt >= file.modifiedAt` then holds by construction.
//
//  A failed write is REPORTED rather than dropped. `createFile` returns a discardable `Bool`, and
//  ignoring it turned a setup failure into a `404`/`500` surfacing as a confusing content assertion
//  three call frames away — which is exactly what makes a rare failure unexplainable after the fact.
//

import Foundation
import Testing

/// Writes a static-file test tree deterministically.
enum FileTree {
    /// Writes `files` into `root`, parents before their sidecars, failing the test on any write error.
    static func write(
        _ files: [String: [UInt8]],
        into root: URL,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let manager = FileManager.default
        // Sorted, not dictionary order: see the file comment — this is what keeps a sidecar from being
        // written before the file it must not be older than.
        for (name, bytes) in files.sorted(by: { $0.key < $1.key }) {
            let path = root.path + "/" + name
            guard manager.createFile(atPath: path, contents: Data(bytes)) else {
                Issue.record(
                    "failed to create the test file \(name) under \(root.path)",
                    sourceLocation: sourceLocation
                )
                return
            }
        }
    }
}
