//
//  RootDirectoryTests.swift
//  HTTPServerTests
//
//  The descriptor-anchored path walk behind static file serving (CWE-22 traversal, CWE-59 link
//  following, CWE-367 time-of-check/time-of-use). Every lookup starts at the root descriptor and takes
//  one `openat(2)` hop per component with `O_NOFOLLOW`, so containment is structural rather than a
//  string comparison, and the descriptor that is verified is the descriptor that is read.
//

import Foundation
import Testing

@testable import HTTPServer

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#endif

@Suite("RootDirectory — structural containment (CWE-22 / CWE-59 / CWE-367)")
struct RootDirectoryTests {
    /// The bytes staged outside the root; no lookup may ever return them.
    private static let secret = "TOP SECRET"

    /// Creates `base/docroot` (the root) and `base/secret/ok.txt` (outside it), returning `base`.
    private func stage() -> String {
        let manager = FileManager.default
        let base = manager.temporaryDirectory
            .appendingPathComponent("rootdirectory-\(UUID().uuidString)").path
        try? manager.createDirectory(atPath: base + "/docroot", withIntermediateDirectories: true)
        try? manager.createDirectory(atPath: base + "/secret", withIntermediateDirectories: true)
        _ = manager.createFile(atPath: base + "/secret/ok.txt", contents: Data(Self.secret.utf8))
        return base
    }

    @Test("a regular file under the root resolves to an open descriptor with its own stat")
    func resolvesRegularFile() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let okFile = base + "/docroot/ok.txt"
        _ = FileManager.default.createFile(atPath: okFile, contents: Data("ok".utf8))

        let root = try #require(RootDirectory(path: base + "/docroot"))
        guard case .file(let file, _) = root.resolve(["ok.txt"]) else {
            Issue.record("the staged regular file did not resolve to a file")
            return
        }
        #expect(file.size == 2)
        #expect(file.modifiedAt > 0)
        #expect(file.read(offset: 0, length: 2) == Array("ok".utf8))
    }

    @Test("an opened file keeps its own bytes when its path is swapped for a symlink (CWE-367)")
    func openedFileSurvivesAPathSwap() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let manager = FileManager.default
        _ = manager.createFile(atPath: base + "/docroot/ok.txt", contents: Data("ok".utf8))

        let root = try #require(RootDirectory(path: base + "/docroot"))
        guard case .file(let file, _) = root.resolve(["ok.txt"]) else {
            Issue.record("the staged regular file did not resolve to a file")
            return
        }
        // The check is done. Land exactly the swap an attacker would race in before the open: the name
        // now points at the secret, but the descriptor already in hand does not.
        try manager.removeItem(atPath: base + "/docroot/ok.txt")
        try manager.createSymbolicLink(
            atPath: base + "/docroot/ok.txt", withDestinationPath: base + "/secret/ok.txt"
        )
        #expect(file.read(offset: 0, length: file.size) == Array("ok".utf8))
        #expect(file.size == 2)  // the stat is the descriptor's, not the name's
    }

    @Test("renaming the root path after startup cannot redirect a lookup (CWE-367)")
    func rootDescriptorIsTheOnlyAnchor() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let manager = FileManager.default
        _ = manager.createFile(atPath: base + "/docroot/ok.txt", contents: Data("ok".utf8))
        _ = manager.createFile(atPath: base + "/secret/ok.txt", contents: Data(Self.secret.utf8))

        let root = try #require(RootDirectory(path: base + "/docroot"))
        // Move the real root aside and put a symlink to the secret directory in its place.
        try manager.moveItem(atPath: base + "/docroot", toPath: base + "/moved")
        try manager.createSymbolicLink(
            atPath: base + "/docroot", withDestinationPath: base + "/secret"
        )
        guard case .file(let file, _) = root.resolve(["ok.txt"]) else {
            Issue.record("the lookup stopped resolving after the root path was replaced")
            return
        }
        #expect(file.read(offset: 0, length: file.size) == Array("ok".utf8))
    }

    @Test("a symlinked final component is refused rather than followed (CWE-59)")
    func symlinkedLeafRefused() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        try FileManager.default.createSymbolicLink(
            atPath: base + "/docroot/leak.txt", withDestinationPath: base + "/secret/ok.txt"
        )
        let root = try #require(RootDirectory(path: base + "/docroot"))
        guard case .refused = root.resolve(["leak.txt"]) else {
            Issue.record("a symlinked final component was not refused")
            return
        }
    }

    @Test("a symlinked intermediate component is refused rather than followed (CWE-59)")
    func symlinkedIntermediateRefused() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        try FileManager.default.createSymbolicLink(
            atPath: base + "/docroot/dir", withDestinationPath: base + "/secret"
        )
        let root = try #require(RootDirectory(path: base + "/docroot"))
        guard case .refused = root.resolve(["dir", "ok.txt"]) else {
            Issue.record("a symlinked intermediate component was not refused")
            return
        }
    }

    @Test("a FIFO under the root is refused rather than opened")
    func fifoRefused() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        #expect(mkfifo(base + "/docroot/pipe", 0o644) == 0)
        let root = try #require(RootDirectory(path: base + "/docroot"))
        // Reaching this assertion at all is the point: `O_NONBLOCK` means the open cannot park waiting
        // for a writer, and the `fstat` then rejects the non-regular file.
        guard case .refused = root.resolve(["pipe"]) else {
            Issue.record("a FIFO was not refused")
            return
        }
    }

    @Test(
        "a malformed or over-deep component list is refused before any syscall",
        arguments: [
            [".."], ["."], ["a", "..", "b"], [""], ["a", "b\0c"],
            [String](repeating: "a", count: 33), ["a", String(repeating: "n", count: 256)]
        ]
    )
    func malformedComponentsRefused(_ components: [String]) throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let root = try #require(RootDirectory(path: base + "/docroot"))
        guard case .refused = root.resolve(components.map { $0[...] }) else {
            Issue.record("\(components) was not refused")
            return
        }
    }

    @Test("a missing name is missing, and a name under a regular file is missing too")
    func missingResolutions() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let okFile = base + "/docroot/ok.txt"
        _ = FileManager.default.createFile(atPath: okFile, contents: Data("ok".utf8))
        let root = try #require(RootDirectory(path: base + "/docroot"))
        guard case .missing = root.resolve(["nope.txt"]) else {
            Issue.record("an absent name did not resolve to missing")
            return
        }
        guard case .missing = root.resolve(["ok.txt", "deeper"]) else {
            Issue.record("a name under a regular file did not resolve to missing")
            return
        }
    }

    @Test("an empty component list resolves to the root directory itself")
    func emptyComponentsResolveToTheRoot() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let okFile = base + "/docroot/ok.txt"
        _ = FileManager.default.createFile(atPath: okFile, contents: Data("ok".utf8))
        let root = try #require(RootDirectory(path: base + "/docroot"))
        guard case .directory(let directory) = root.resolve([]) else {
            Issue.record("the empty component list did not resolve to a directory")
            return
        }
        #expect(directory.openFile(named: "ok.txt")?.size == 2)
        #expect(directory.openFile(named: "..") == nil)  // never a traversal, even from a directory
    }

    @Test(
        "a read short of the requested length fails closed rather than returning a partial buffer")
    func shortReadFailsClosed() throws {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        _ = FileManager.default.createFile(
            atPath: base + "/docroot/ok.txt", contents: Data("0123456789".utf8)
        )
        let root = try #require(RootDirectory(path: base + "/docroot"))
        guard case .file(let file, _) = root.resolve(["ok.txt"]) else {
            Issue.record("the staged regular file did not resolve to a file")
            return
        }
        #expect(truncate(base + "/docroot/ok.txt", 4) == 0)
        #expect(file.read(offset: 0, length: 10) == nil)  // the framed length can no longer be met
        #expect(file.read(offset: 0, length: 4) == Array("0123".utf8))
    }

    @Test("a root that is not an existing directory does not open")
    func unopenableRoot() {
        let base = stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        _ = FileManager.default.createFile(atPath: base + "/plain", contents: Data("x".utf8))
        #expect(RootDirectory(path: base + "/plain") == nil)  // a regular file is not a root
        #expect(RootDirectory(path: base + "/absent") == nil)
    }
}
