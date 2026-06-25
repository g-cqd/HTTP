//
//  Recorder.swift
//  HTTPServerTests
//
//  The middleware abstraction: chain ordering (outermost-first), short-circuiting, and the built-in
//  Server-header, access-log, and CORS middlewares.
//

import Synchronization

/// A thread-safe ordered recorder for chain-order and log assertions.
final class Recorder: Sendable {
    private let storage = Mutex<[String]>([])

    func add(_ entry: String) { storage.withLock { $0.append(entry) } }

    var entries: [String] { storage.withLock(\.self) }

    deinit {
        // No teardown beyond ARC.
    }
}
