//
//  ConstrainedStack.swift
//  HTTPTestSupport
//
//  Runs work on a freshly spawned thread whose stack is pinned small, so the project's "no recursion /
//  no stack exhaustion on adversarial input" mandate is CI-enforced: an accidental recursive descent
//  in a parser overflows the tiny stack and SIGBUSes (a hard failure) instead of passing silently on
//  the multi-MB main test stack.
//

internal import Foundation

/// Runs `body` on a freshly spawned thread whose stack is pinned to `stackSize`, returning its result.
///
/// Survival of the join *is* the assertion: a stack overflow inside `body` kills the process with
/// SIGBUS rather than returning, so any caller that completes has proven the work fits. `body` must be
/// total (catch its own errors); only an unrecoverable overflow should fail to return. No recursion
/// here — the depth lives entirely in `body`.
public func runOnConstrainedStack<R: Sendable>(
    stackSize: Int = 512 * 1_024,
    name: String = "HTTPTestSupport.constrained-stack",
    _ body: @escaping @Sendable () -> R
) -> R {
    let box = ResultBox<R>()
    let done = DispatchSemaphore(value: 0)
    let worker = Thread {
        box.set(body())
        done.signal()
    }
    worker.stackSize = stackSize
    worker.name = name
    worker.start()
    done.wait()
    return box.take()
}

/// The `Void` specialization: runs `body` on the pinned stack and blocks until it returns.
public func runOnConstrainedStack(
    stackSize: Int = 512 * 1_024,
    name: String = "HTTPTestSupport.constrained-stack",
    _ body: @escaping @Sendable () -> Void
) {
    let _: Int = runOnConstrainedStack(stackSize: stackSize, name: name) {
        body()
        return 0
    }
}

/// A minimal `Sendable` hand-off so the constrained-stack worker can ferry its result back.
private final class ResultBox<R: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: R?

    deinit {
        // No teardown beyond ARC.
    }

    func set(_ newValue: R) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    func take() -> R {
        lock.lock()
        defer { lock.unlock() }
        guard let value else { preconditionFailure("constrained-stack worker produced no result") }
        return value
    }
}
