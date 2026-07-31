//
//  ReactorProbeExecutor.swift
//  HTTPServerTests
//
//  A stand-in for a transport's serial event loop, plus the "am I on it right now?" question the
//  execution-policy suites are built on (audit CR-F7).
//
//  A `TransportConnection`'s `preferredTaskExecutor` is what pins a connection's whole serve
//  hierarchy to one reactor thread. To assert *which* work still runs there and which was lifted off
//  it, a test needs a preferred executor it recognizes. This is that executor: one serial
//  `DispatchQueue` carrying a `DispatchSpecificKey`, so any code — production code called from a test
//  fake, in particular — can ask ``isCurrent`` and get a truthful answer with no instrumentation in
//  the server itself.
//
//  `DispatchQueue.getSpecific` reads the *current* queue's value, and a job run by ``enqueue(_:)``
//  runs synchronously inside `queue.async`, so the key is set for exactly the span of that job. That
//  is the whole mechanism; there is no bookkeeping to get out of step.
//

import Dispatch

/// A serial ``TaskExecutor`` that can be asked whether it is the one currently running.
final class ReactorProbeExecutor: TaskExecutor, @unchecked Sendable {
    /// The marker read by ``isCurrent`` — set on this executor's queue only.
    private static let key = DispatchSpecificKey<ObjectIdentifier>()

    private let queue: DispatchQueue

    /// Creates a serial executor labelled `label`, distinguishable from every other instance.
    init(label: String = "reactor.probe") {
        queue = DispatchQueue(label: label)
        queue.setSpecific(key: Self.key, value: ObjectIdentifier(self))
    }

    deinit {
        // No teardown beyond ARC; the queue releases with the instance.
    }

    /// Whether the caller is running on this executor's serial queue.
    var isCurrent: Bool {
        DispatchQueue.getSpecific(key: Self.key) == ObjectIdentifier(self)
    }

    func enqueue(_ job: consuming ExecutorJob) {
        let unowned = UnownedJob(job)
        queue.async { unowned.runSynchronously(on: self.asUnownedTaskExecutor()) }
    }
}
