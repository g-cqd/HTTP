//
//  Allocations.swift
//  HTTPTestSupport
//
//  A heap-allocation perf guard for unit tests, backing the project's zero-allocation hot-path goal
//  (200k rps). `expectAllocations(noMoreThan:)` trips when a re-introduced copy / box / un-reserved
//  growth lands on a measured path — complementing the benchmark `.mallocCountTotal` metric.
//

internal import CHTTPTestMalloc
public import Testing

/// Whether process-wide allocation counting is available here.
///
/// Darwin: `true` (libmalloc hook). Other platforms: `false` — the oracle then runs the body but
/// cannot measure, so ``expectAllocations(noMoreThan:sourceLocation:_:)`` becomes a no-op there.
public var allocationCountingAvailable: Bool { httptk_malloc_counting_available() != 0 }

/// Counts the heap allocations made during `body`.
///
/// Run a SYNCHRONOUS body with no concurrent work (the count is process-wide) and WARM UP first (call
/// the body once before measuring) so one-time lazy initialization doesn't skew the delta. Returns
/// `nil` where counting is unavailable (the body still runs, for its side effects).
public func mallocDelta(_ body: () -> Void) -> Int? {
    guard httptk_malloc_counting_available() != 0 else {
        body()
        return nil
    }
    httptk_malloc_count_begin()
    body()
    return Int(httptk_malloc_count_end())
}

/// Asserts `body` makes at most `limit` heap allocations — a mutation-resistant performance guard.
///
/// A re-introduced copy / box / un-reserved growth on a hot path trips it. Warm up + measure
/// synchronously (see ``mallocDelta(_:)``). Where counting is unavailable it runs the body and
/// records nothing (no false failure); returns the measured count (`nil` if unavailable).
@discardableResult
public func expectAllocations(
    noMoreThan limit: Int,
    sourceLocation: SourceLocation = #_sourceLocation,
    _ body: () -> Void
) -> Int? {
    guard let count = mallocDelta(body) else { return nil }
    if count > limit {
        Issue.record(
            "expected at most \(limit) allocation(s), measured \(count)",
            sourceLocation: sourceLocation)
    }
    return count
}
