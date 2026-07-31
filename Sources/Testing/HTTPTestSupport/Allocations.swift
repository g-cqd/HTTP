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
/// Run a SYNCHRONOUS body and WARM UP first (call the body once before measuring) so one-time lazy
/// initialization doesn't skew the delta. Counting is per measuring thread, so a concurrently running
/// test does not inflate the count — but allocations the body makes on *other* threads are likewise not
/// counted. Returns `nil` where counting is unavailable (the body still runs, for its side effects).
public func mallocDelta(_ body: () -> Void) -> Int? {
    guard httptk_malloc_counting_available() != 0 else {
        body()
        return nil
    }
    httptk_malloc_count_begin()
    body()
    return Int(httptk_malloc_count_end())
}

/// Counts the heap octets requested during `body`.
///
/// Same rules as ``mallocDelta(_:)`` (synchronous body, warm up first, per measuring thread). The
/// total is *cumulative requested size*, not peak residency: a grow-copy-free loop is charged for
/// every intermediate buffer. That is what makes it the right oracle for bounded growth — a routine
/// that sizes one buffer straight to a hard cap and one that grows geometrically to a much smaller
/// final size make a similar number of allocations and differ by orders of magnitude in octets.
public func mallocByteDelta(_ body: () -> Void) -> Int? {
    guard httptk_malloc_counting_available() != 0 else {
        body()
        return nil
    }
    var bytes: UInt64 = 0
    httptk_malloc_count_begin()
    body()
    httptk_malloc_count_stop(nil, &bytes)
    return Int(bytes)
}

/// Asserts `body` requests at most `limit` heap octets — the bounded-growth guard.
///
/// Trips when a routine starts sizing a buffer to its worst-case bound instead of growing into it —
/// the decompression-bomb shape, where a small input plus a large cap must not become a large
/// allocation (CWE-409). Where counting is unavailable it runs the body and records nothing.
@discardableResult
public func expectAllocatedBytes(
    noMoreThan limit: Int,
    sourceLocation: SourceLocation = #_sourceLocation,
    _ body: () -> Void
) -> Int? {
    guard let bytes = mallocByteDelta(body) else {
        return nil
    }
    if bytes > limit {
        Issue.record(
            "expected at most \(limit) allocated octet(s), measured \(bytes)",
            sourceLocation: sourceLocation
        )
    }
    return bytes
}

/// Asserts `body` makes at most `limit` heap allocations — a mutation-resistant performance guard.
///
/// A re-introduced copy / box / un-reserved growth on a hot path trips it. Warm up + measure
/// synchronously (see ``mallocDelta(_:)``). Where counting is unavailable it runs the body and
/// records nothing (no false failure); returns the measured count (`nil` if unavailable). Counting is
/// per-thread, so a suite running in parallel does not inflate the measurement.
@discardableResult
public func expectAllocations(
    noMoreThan limit: Int,
    sourceLocation: SourceLocation = #_sourceLocation,
    _ body: () -> Void
) -> Int? {
    guard let count = mallocDelta(body) else {
        return nil
    }
    if count > limit {
        Issue.record(
            "expected at most \(limit) allocation(s), measured \(count)",
            sourceLocation: sourceLocation
        )
    }
    return count
}
