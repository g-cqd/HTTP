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

/// A canonical depth sweep for recursion-cap regression locks.
///
/// Shallow values, each cap straddled at `cap-1 / cap / cap+1`, and a far-past-cap depth — run on a
/// constrained stack so a missing or mis-sized cap surfaces as a SIGBUS rather than passing silently.
/// Built iteratively (no recursion in the kit).
public struct DepthSweep: Sendable {
    /// The depths to sweep, in ascending order.
    public let depths: [Int]

    /// Creates a sweep over explicit `depths`.
    public init(depths: [Int]) { self.depths = depths }

    /// A sweep straddling each cap in `caps`, from shallow up to `maxDepth` (sorted, de-duplicated).
    public static func around(_ caps: [Int], upTo maxDepth: Int = 3_000) -> Self {
        var set = Set<Int>([1, 8, 16, 32])
        for cap in caps where cap > 0 {
            set.insert(cap - 1)
            set.insert(cap)
            set.insert(cap + 1)
        }
        set.insert(maxDepth / 3)
        set.insert(maxDepth)
        let depths = set.filter { $0 >= 1 && $0 <= maxDepth }.sorted()
        return Self(depths: depths)
    }

    /// A variadic convenience over ``around(_:upTo:)``.
    public static func around(_ caps: Int..., upTo maxDepth: Int = 3_000) -> Self {
        around(caps, upTo: maxDepth)
    }

    /// Runs `body(depth)` on a constrained stack at each swept depth.
    ///
    /// `body` is expected to be total — it should evaluate the depth-`n` shape and record any
    /// unexpected outcome itself; reaching the end of the sweep proves none overflowed.
    public func run(
        stackSize: Int = 512 * 1_024,
        name: String = "HTTPTestSupport.depth-sweep",
        _ body: @escaping @Sendable (Int) -> Void
    ) {
        for depth in depths {
            runOnConstrainedStack(stackSize: stackSize, name: name) { body(depth) }
        }
    }
}
