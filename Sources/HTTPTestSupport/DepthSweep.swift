//
//  DepthSweep.swift
//  HTTPTestSupport
//
//  A canonical depth sweep for recursion-cap regression locks: shallow values, each cap straddled at
//  `cap-1 / cap / cap+1`, and a far-past-cap depth — each run on a constrained stack so a missing or
//  mis-sized cap surfaces as a SIGBUS rather than passing silently. Built iteratively (no recursion).
//

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
