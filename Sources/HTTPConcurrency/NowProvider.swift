//
//  NowProvider.swift
//  HTTPConcurrency
//
//  The injection point for elapsed-time logic (the HTTP/2 Rapid Reset rolling window, future request
//  timing) — monotonic nanoseconds, never the wall clock, so it cannot run backwards. A library takes
//  `now: MonotonicNowProvider = LiveMonotonicClock.now`; a test passes a closure over a manual clock,
//  pinning time with zero real waiting. Reuse-safe; the only platform import is the monotonic syscall.
//

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#endif

/// A monotonic timestamp in nanoseconds — the unit elapsed-time/rate logic measures against, as
/// `Int64` so a test can pin it without a real clock.
public typealias MonotonicNanoseconds = Int64

/// The injection point for "how many monotonic nanoseconds have elapsed".
///
/// A rate limiter takes `now: MonotonicNowProvider = LiveMonotonicClock.now` and a test passes a
/// closure returning a controllable instant — the first deterministic time-windowed defense.
public typealias MonotonicNowProvider = @Sendable () -> MonotonicNanoseconds

/// The shipped live default the ``MonotonicNowProvider`` seam points at: a pure `CLOCK_MONOTONIC`
/// read, so defaulting to it changes nothing in production; only a test overrides it.
public enum LiveMonotonicClock {
    /// Monotonic nanoseconds (`CLOCK_MONOTONIC`) for elapsed-time measurement.
    public static let now: MonotonicNowProvider = {
        var ts = timespec()
        clock_gettime(CLOCK_MONOTONIC, &ts)
        return Int64(ts.tv_sec) &* 1_000_000_000 &+ Int64(ts.tv_nsec)
    }
}

extension Duration {
    /// This duration as whole nanoseconds (saturating, non-negative), the unit a
    /// ``MonotonicNowProvider`` measures against.
    ///
    /// A `streamResetInterval` of `.seconds(1)` becomes `1_000_000_000` for comparison against
    /// monotonic timestamps.
    public var monotonicNanoseconds: MonotonicNanoseconds {
        let (seconds, attoseconds) = components
        let (scaled, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000_000)
        guard !overflow else {
            return .max
        }
        let (total, addOverflow) = scaled.addingReportingOverflow(attoseconds / 1_000_000_000)
        return addOverflow ? .max : max(0, total)
    }
}
