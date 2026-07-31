//
//  FileResponderSymlinkRaceTests.swift
//  HTTPServerTests
//
//  The audit's TOCTOU regressions for ``FileResponder`` (CWE-367 time-of-check/time-of-use, CWE-59 link
//  following). A writer races `rename(2)` against concurrent requests, swapping a path component between
//  a real tree and a symlink to a directory outside the root, while the responder serves the same URL
//  over and over. The old shape — resolve symlinks, compare string prefixes, then open BY NAME — leaked
//  the outside file through that window; the descriptor-anchored walk cannot, because the descriptor that
//  was verified is the descriptor that is read.
//
//  The pass condition is absolute: every response must be `200` carrying the in-root bytes, or `403`, or
//  `404`. No body may ever contain the staged secret. These run clean under `--sanitize=thread`.
//
//  Standards: rename() per POSIX.1-2017 (IEEE Std 1003.1-2017); renamex_np(RENAME_SWAP) per Darwin
//  <sys/stdio.h> for the atomic directory/symlink exchange.
//

import Foundation
import HTTPCore
import Testing

@testable import HTTPServer

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#endif

@Suite("FileResponder — rename races cannot leak outside the root (CWE-367 / CWE-59)")
struct FileResponderSymlinkRaceTests {
    /// The bytes staged outside the root; no response body may ever contain them.
    private static let secret = "TOP SECRET"

    /// The bytes staged inside the root; the only body a `200` is allowed to carry.
    private static let served = "ok"

    // MARK: The deterministic proofs (no race needed)

    @Test("a streamed response keeps its own bytes when its path is swapped mid-flight (CWE-367)")
    func streamedRegionSurvivesAPathSwap() async throws {
        let base = Self.stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let manager = FileManager.default
        let expected = [UInt8](repeating: 0x41, count: 4_096)
        manager.createFile(atPath: base + "/docroot/big.bin", contents: Data(expected))
        manager.createFile(
            atPath: base + "/secret/big.bin",
            contents: Data([UInt8](repeating: 0x5A, count: 4_096))
        )

        // Over the threshold, so the response carries a lazy stream holding the verified descriptor.
        let responder = FileResponder(root: base + "/docroot", streamingThreshold: 1_024)
        let response = await responder.respond(to: Self.get("/big.bin"), body: [])
        #expect(response.head.headerFields[.contentLength] == "4096")

        // The check is done and the head is framed. Land the swap an attacker would race in before a
        // single body octet is produced: the name now points outside the root, the descriptor does not.
        try manager.removeItem(atPath: base + "/docroot/big.bin")
        try manager.createSymbolicLink(
            atPath: base + "/docroot/big.bin", withDestinationPath: base + "/secret/big.bin"
        )
        #expect(await response.stream?.collect(maxBytes: 1 << 20) == expected)
    }

    @Test("a symlinked final component is refused with 403, not followed (CWE-59)")
    func symlinkedLeafRefused() async throws {
        let base = Self.stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        try FileManager.default.createSymbolicLink(
            atPath: base + "/docroot/ok.txt", withDestinationPath: base + "/secret/ok.txt"
        )
        let responder = FileResponder(root: base + "/docroot")
        let response = await responder.respond(to: Self.get("/ok.txt"), body: [])
        #expect(response.head.status == .forbidden)
        #expect(response.body.isEmpty)
    }

    @Test("a FIFO under the root is refused with 403 rather than opened")
    func fifoRefused() async {
        let base = Self.stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        #expect(mkfifo(base + "/docroot/ok.txt", 0o644) == 0)
        let responder = FileResponder(root: base + "/docroot")
        // Returning at all is the assertion: `O_NONBLOCK` keeps the open from parking on a FIFO with no
        // writer, which would otherwise wedge this serve task (and, in production, the connection).
        let response = await responder.respond(to: Self.get("/ok.txt"), body: [])
        #expect(response.head.status == .forbidden)
        #expect(response.body.isEmpty)
    }

    // MARK: The races

    @Test("swapping the final component for a symlink under concurrent load never leaks (CWE-367)")
    func leafSwapRace() async {
        let base = Self.stage()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let manager = FileManager.default
        try? manager.createDirectory(
            atPath: base + "/docroot/dir", withIntermediateDirectories: true
        )
        manager.createFile(
            atPath: base + "/docroot/dir/ok.txt", contents: Data(Self.served.utf8)
        )

        // Stage the next incarnation beside the target, then land it with an atomic rename(2): a real
        // "ok" file on an odd round, a symlink pointing at the secret outside the root on an even one.
        let swap: @Sendable (Int) -> Void = { round in
            let staging = base + "/stage/next"
            unlink(staging)
            if round.isMultiple(of: 2) {
                _ = symlink(base + "/secret/ok.txt", staging)
            }
            else {
                Self.stageRegularFile(Self.served, at: staging)
            }
            _ = rename(staging, base + "/docroot/dir/ok.txt")
        }
        let responder = FileResponder(root: base + "/docroot")
        // Both sides are live, asserted outside the race — which side a racing request lands on is by
        // definition not something to assert on, but a race between two identical states proves nothing.
        await Self.expectStatus(responder, "/dir/ok.txt", .ok)
        swap(0)
        await Self.expectStatus(responder, "/dir/ok.txt", .forbidden)

        let outcomes = await Self.race(responder, path: "/dir/ok.txt", swap: swap)
        #expect(Self.leaks(outcomes).isEmpty, "\(Self.leaks(outcomes).prefix(5))")
    }

    #if canImport(Darwin)
        @Test("swapping a directory for a symlink under concurrent load never leaks (CWE-367)")
        func directorySwapRace() async {
            let base = Self.stage()
            defer { try? FileManager.default.removeItem(atPath: base) }
            let manager = FileManager.default
            try? manager.createDirectory(
                atPath: base + "/docroot/dir", withIntermediateDirectories: true
            )
            manager.createFile(
                atPath: base + "/docroot/dir/ok.txt", contents: Data(Self.served.utf8)
            )
            try? manager.createSymbolicLink(
                atPath: base + "/stage/dir", withDestinationPath: base + "/secret"
            )

            // RENAME_SWAP exchanges the two names atomically, so `docroot/dir` alternates between a real
            // directory and a symlink to the secret with no window in which it is absent.
            let swap: @Sendable (Int) -> Void = { _ in
                _ = renamex_np(base + "/stage/dir", base + "/docroot/dir", UInt32(RENAME_SWAP))
            }
            let responder = FileResponder(root: base + "/docroot")
            await Self.expectStatus(responder, "/dir/ok.txt", .ok)
            swap(0)
            await Self.expectStatus(responder, "/dir/ok.txt", .forbidden)

            let outcomes = await Self.race(responder, path: "/dir/ok.txt", swap: swap)
            #expect(Self.leaks(outcomes).isEmpty, "\(Self.leaks(outcomes).prefix(5))")
        }
    #endif

    // MARK: Fixtures

    /// Creates `base/docroot` (the root), `base/secret/ok.txt` (outside it), and `base/stage`.
    private static func stage() -> String {
        let manager = FileManager.default
        let base = manager.temporaryDirectory
            .appendingPathComponent("fileresponder-race-\(UUID().uuidString)").path
        for child in ["/docroot", "/secret", "/stage"] {
            try? manager.createDirectory(atPath: base + child, withIntermediateDirectories: true)
        }
        manager.createFile(atPath: base + "/secret/ok.txt", contents: Data(secret.utf8))
        return base
    }

    /// Writes `contents` to `path`, replacing whatever is there.
    private static func stageRegularFile(_ contents: String, at path: String) {
        let file = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        guard file >= 0 else {
            return
        }
        let bytes = Array(contents.utf8)
        _ = bytes.withUnsafeBytes { buffer in
            write(file, buffer.baseAddress, buffer.count)
        }
        close(file)
    }

    private static func get(_ path: String) -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "x", path: path)
    }

    /// Asserts the status of one uncontended request for `path`.
    private static func expectStatus(
        _ responder: FileResponder,
        _ path: String,
        _ expected: HTTPStatus,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async {
        let response = await responder.respond(to: get(path), body: [])
        #expect(response.head.status == expected, sourceLocation: sourceLocation)
    }

    // MARK: The harness

    /// The leaks in `outcomes` — the responses that were neither the in-root `200` nor a `403`/`404`.
    private static func leaks(_ outcomes: [String]) -> [String] {
        outcomes.filter { $0.hasPrefix(leakTag) }
    }

    /// The prefix ``probe(_:path:count:)`` marks a disallowed outcome with.
    private static let leakTag = "LEAK "

    /// Runs `swap` in a loop against `readers` tasks each requesting `path`, and returns one outcome tag
    /// per response.
    private static func race(
        _ responder: FileResponder,
        path: String,
        readers: Int = 6,
        requests: Int = 200,
        swaps: Int = 1_500,
        swap: @escaping @Sendable (Int) -> Void
    ) async -> [String] {
        await withTaskGroup(of: [String].self) { group in
            group.addTask {
                for round in 0 ..< swaps {
                    swap(round)
                    await Task.yield()  // never monopolise a cooperative thread from a test
                }
                return []
            }
            for _ in 0 ..< readers {
                group.addTask {
                    await probe(responder, path: path, count: requests)
                }
            }
            var outcomes: [String] = []
            for await result in group {
                outcomes.append(contentsOf: result)
            }
            return outcomes
        }
    }

    /// Requests `path` `count` times, tagging each response as an allowed status or as a leak.
    private static func probe(
        _ responder: FileResponder,
        path: String,
        count: Int
    ) async -> [String] {
        var outcomes: [String] = []
        for _ in 0 ..< count {
            // `respond` never actually suspends for a static file, so without this the reader tasks
            // would run to completion without the swapper ever being scheduled — no race at all.
            await Task.yield()
            let response = await responder.respond(to: get(path), body: [])
            let status = response.head.status
            let body = String(bytes: response.body, encoding: .utf8) ?? "<non-utf8>"
            if status == .ok, body == served {
                outcomes.append("200")
            }
            else if status == .forbidden || status == .notFound, response.body.isEmpty {
                outcomes.append("\(status)")
            }
            else {
                outcomes.append("\(leakTag)\(status) body=\(body)")
            }
        }
        return outcomes
    }
}
