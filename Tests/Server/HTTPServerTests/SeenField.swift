//
//  SeenField.swift
//  HTTPServerTests
//
//  The slot ``RecordingUpgradeHandler`` writes into: what the WebSocket upgrade authorization seam was
//  handed for one named field, captured across the server's task boundaries (audit R5-SEC1).
//

import Synchronization

/// The `Mutex`-guarded slot ``RecordingUpgradeHandler`` writes what it saw into.
final class SeenField: Sendable {
    /// `.none` until the upgrade seam runs; then `.some(value)`, itself optional when the field was
    /// absent — the distinction that separates "never asked" from "asked, and it was stripped".
    private let value = Mutex<String??>(nil)

    deinit {
        // No teardown beyond ARC; the mutex releases with the instance.
    }

    func record(_ newValue: String?) {
        value.withLock { $0 = .some(newValue) }
    }

    /// Whether the seam ran at all.
    var wasAsked: Bool { value.withLock { $0 != nil } }

    /// The value the seam was handed, flattened: nil both when it never ran and when the field was
    /// absent — read together with ``wasAsked``.
    var recorded: String? { value.withLock { $0.flatMap(\.self) } }
}
