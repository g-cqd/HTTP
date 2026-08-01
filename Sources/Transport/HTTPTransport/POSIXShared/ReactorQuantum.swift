//
//  ReactorQuantum.swift
//  HTTPTransport
//
//  The fairness budgets shared by the kqueue and epoll reactors (PERF-1), and the monotonic clock they
//  are measured against.
//
//  Both loops used to drain their inbox `while !isEmpty` and their listener until `EAGAIN`, with no
//  bound at all. One busy source could therefore hold the loop thread for as long as it had work, and
//  every other socket on that reactor — every other connection, since connections are pinned to a loop
//  for life — waited behind it. A burst of preferred-executor jobs could starve socket readiness
//  outright. That is a fairness failure, and under an accept storm or a job flood it is also a
//  denial-of-service amplifier (CWE-400, uncontrolled resource consumption): the work is admitted, so
//  the only thing that degrades is everyone else's latency.
//
//  Standards: kqueue/kevent (Darwin manuals), epoll (Linux manuals), accept(2) per POSIX.1-2017.
//

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// How much work one reactor turn may do before it must go back and service readiness.
enum ReactorQuantum {
    /// How long one inbox drain may run before yielding to the readiness wait.
    ///
    /// Chosen against the two costs that bracket it, measured on this host (provisional — see the
    /// commit body): a `kevent` round trip with a zero timeout is ~19.5 us, and a monotonic clock read
    /// is ~11 ns. So yielding after *every* drain turn (the obvious alternative) would pay a ~19.5 us
    /// syscall per turn, while a time budget costs a clock read. 1 ms is ~50x the syscall it forces, so
    /// the fairness cost is roughly 2% of the loop's syscall budget in the worst case, and it bounds
    /// how long socket readiness can be starved to about one millisecond — under the ~2 ms floor where
    /// added latency starts being visible in a p99.
    static let drainNanoseconds: UInt64 = 1_000_000

    /// How many jobs run between clock reads inside one drain.
    ///
    /// The budget is only honored at this granularity, so it trades precision for the cost of the
    /// check. At 64, a drain that runs 64 jobs of 1 us each overshoots the budget by at most ~64 us,
    /// and the clock read is ~11 ns per 64 jobs — under a thousandth of a percent.
    static let clockCheckStride = 64

    /// How many connections one accept-readiness turn may take before re-arming.
    ///
    /// The listener drains until `EAGAIN`, so under an accept storm the loop stayed in `accept(2)` for
    /// as long as the backlog held — while the connections it had *already* accepted waited. Re-arming
    /// after a bounded batch puts the listener back in the readiness set behind the live sockets rather
    /// than ahead of them; nothing is dropped, because an un-drained backlog leaves the listener
    /// immediately readable again. 256 is the batch a single `kevent`/`epoll_wait` turn already reports
    /// (both loops use a 256-entry event buffer), so accept keeps parity with readiness rather than
    /// out-running it.
    static let acceptBatch = 256

    /// A monotonic timestamp in nanoseconds — never wall time, so a clock adjustment cannot extend or
    /// collapse a quantum.
    static func nanoseconds() -> UInt64 {
        #if canImport(Darwin)
            return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
        #else
            var now = timespec()
            clock_gettime(CLOCK_MONOTONIC, &now)
            return UInt64(now.tv_sec) &* 1_000_000_000 &+ UInt64(now.tv_nsec)
        #endif
    }
}
