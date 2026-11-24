//
//  TestClock+HTTPConcurrency.swift
//  HTTPTestSupport
//
//  Bridges `AemiTestKit.TestClock` to `HTTPConcurrency`'s `MonotonicNanoseconds` /
//  `MonotonicNowProvider` seam so rate-limit and rolling-window tests can drive elapsed time
//  directly from `TestClock`.
//

public import AemiTestKit
public import HTTPConcurrency

extension TestClock {
    /// This clock's elapsed time as monotonic nanoseconds — the unit the ``MonotonicNowProvider``
    /// seam measures against.
    public var monotonicNanoseconds: MonotonicNanoseconds { now.offset.monotonicNanoseconds }

    /// A ``MonotonicNowProvider`` backed by this clock, so injecting it into rate limiters or the
    /// HTTP/2 engine makes time advance deterministically with ``advance(by:)``.
    public var nowProvider: MonotonicNowProvider {
        { [self] in monotonicNanoseconds }
    }
}
