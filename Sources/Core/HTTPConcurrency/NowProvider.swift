//
//  NowProvider.swift
//  HTTPConcurrency
//
//  Thin compatibility facade over `AemiRuntime`'s `LiveClock.monotonicNanoseconds` and
//  `MonotonicNanoseconds` so existing HTTP callers keep `MonotonicNowProvider` /
//  `LiveMonotonicClock.now` while sharing the single canonical monotonic clock implementation in
//  `AemiRuntime`.
//

public import AemiRuntime

/// The injection point for "how many monotonic nanoseconds have elapsed".
///
/// Alias of `AemiRuntime.MonotonicNanosecondsProvider`.
public typealias MonotonicNowProvider = AemiRuntime.MonotonicNanosecondsProvider

/// The shipped live default the ``MonotonicNowProvider`` seam points at: delegates directly to
/// `AemiRuntime.LiveClock.monotonicNanoseconds`.
public enum LiveMonotonicClock {
    /// Monotonic nanoseconds (`CLOCK_MONOTONIC`) for elapsed-time measurement.
    public static let now: MonotonicNowProvider = AemiRuntime.LiveClock.monotonicNanoseconds
}
