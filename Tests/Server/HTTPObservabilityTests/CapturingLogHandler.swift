//
//  CapturingLogHandler.swift
//  HTTPObservabilityTests
//
//  A swift-log `LogHandler` that records every emitted entry into a shared, thread-safe store, so a test
//  can assert on the structured metadata `LoggingMiddleware` produces.
//

import Logging
import Synchronization

/// A `LogHandler` capturing emitted entries into a shared `Store` for assertions.
struct CapturingLogHandler: LogHandler {
    /// One captured log entry — the level and the call-site metadata.
    struct Entry: Sendable {
        let level: Logger.Level
        let metadata: Logger.Metadata
    }

    /// The shared sink the (value-type) handler appends captured entries to.
    final class Store: Sendable {
        private let storage = Mutex<[Entry]>([])

        deinit {
            // No teardown beyond ARC; the Mutex releases with the instance.
        }

        var entries: [Entry] {
            storage.withLock(\.self)
        }

        func append(_ entry: Entry) {
            storage.withLock { $0.append(entry) }
        }
    }

    let store: Store
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace

    init(_ store: Store) {
        self.store = store
    }

    func log(event: LogEvent) {
        store.append(Entry(level: event.level, metadata: event.metadata ?? [:]))
    }

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }
}
