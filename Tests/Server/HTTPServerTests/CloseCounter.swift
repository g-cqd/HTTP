//
//  CloseCounter.swift
//  HTTPServerTests
//
//  A cross-task counter for ``CountingWebSocketHandler``: `onClose` runs on a tunnel pump task while
//  the test asserts from its own, so the count has to be shared safely.
//

import Synchronization

/// Counts `onClose` invocations across tasks.
final class CloseCounter: Sendable {
    private let count = Atomic<Int>(0)

    var value: Int { count.load(ordering: .sequentiallyConsistent) }

    func bump() { count.wrappingAdd(1, ordering: .sequentiallyConsistent) }

    deinit {
        // No teardown beyond ARC.
    }
}
