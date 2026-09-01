//
//  ExecutionTopology.swift
//  httpd-example
//
//  The three routes that make ``HandlerExecutionPolicy`` measurable (2026-07-31 audit, CR-F7), and
//  the environment parsing that selects a policy — see `docs/adr/0007-handler-execution-policy.md`
//  for the decision this exists to answer and the rule it is answered against.
//
//  Behind `HTTPD_EXEC_ROUTES=1`, deliberately. The five-route parity set (`/`, `/json`, `/payload`,
//  `/hello/world`, `POST /echo`) is what `Benchmarking/Bench/run.sh` compares against nginx, caddy,
//  Go, Bun, Rust, Hummingbird, Vapor and Django, and every one of those servers implements exactly
//  that set. Adding routes to the shared table would change what the comparative harness measures for
//  a question it is not being asked. Off by default, the parity set is byte-identical.
//
//  The three shapes are chosen because they fail differently under a serial reactor:
//
//    /exec/trivial — the cost of the POLICY. Nothing but a tiny body, so the only difference between
//                    `.inline` and `.concurrent` on this route is the executor hop itself. This is
//                    the route the decision rule's regression clauses are stated against.
//    /exec/cpu     — the PARALLELISM case. ~2 ms of real arithmetic: pinned to a reactor, N of these
//                    on one shard serialize; off it they use N cores.
//    /exec/block   — the ISOLATION case. `Thread.sleep` holds a THREAD rather than suspending a task,
//                    which is what a filesystem call, a synchronous compression pass, a `libcrypto`
//                    verify or a blocking log sink actually does to a reactor.
//
//  Standards: these are plain `GET`s (RFC 9110 §9.3.1) returning `text/plain`; nothing here is a
//  protocol feature, only a workload shape.
//

import Foundation
import HTTPServer

/// The workload routes and policy selection for the execution-topology measurement (audit CR-F7).
enum ExecutionTopology {
    /// Iterations of ``burn(_:)`` that take approximately 2 ms.
    ///
    /// CALIBRATED ONCE AND PINNED, on purpose. A route that re-calibrates at startup would make two
    /// runs of the harness incomparable, which is exactly what a benchmark route must not do. The
    /// value is therefore machine-specific by construction: it was measured on the host recorded in
    /// ADR 0007, and a different machine will see a different per-request duration from the same
    /// count. That is the correct trade — the constant is what is held fixed across a comparison, not
    /// the duration.
    ///
    /// Measured at 1.74 / 1.94 / 1.74 ms (best of 20, three consecutive runs) on Apple silicon, a
    /// release build, 2026-08-01. Re-derive with `HTTPD_EXEC_CALIBRATE=1`, which prints the measured
    /// cost of this count and exits without serving.
    static let cpuIterations = 655_360

    /// How long ``blockingRoute()`` holds its thread.
    ///
    /// 10 ms is the order of a small synchronous filesystem read or a public-key verification — long
    /// enough to be unmistakable against a sub-millisecond trivial route, short enough that a client
    /// with a normal timeout still completes.
    static let blockingDuration = 0.010

    /// Whether the execution-topology routes are registered (`HTTPD_EXEC_ROUTES=1`).
    static var isEnabled: Bool {
        ProcessInfo.processInfo.environment["HTTPD_EXEC_ROUTES"] == "1"
    }

    /// The routes, or none when the flag is unset — `RouteBuilder.buildExpression([Route])` lifts the
    /// array into the table.
    static func routes() -> [Route] {
        guard isEnabled else {
            return []
        }
        return [trivialRoute(), cpuRoute(), blockingRoute()]
    }

    /// The handler execution policy from `HTTPD_HANDLER_EXEC`, defaulting to `.inline`.
    ///
    /// Accepts `inline`, `concurrent`, and `adaptive` with an optional threshold in milliseconds
    /// (`adaptive:2` means "hop a route once it measures over 2 ms"). An unrecognized value falls
    /// back to the shipped default rather than failing, so a typo in a harness environment cannot
    /// silently produce a run of some third thing.
    static func policy() -> HandlerExecutionPolicy {
        let raw = ProcessInfo.processInfo.environment["HTTPD_HANDLER_EXEC"] ?? "inline"
        let parts = raw.split(separator: ":", maxSplits: 1)
        switch parts.first {
            case "concurrent":
                return .concurrent
            case "adaptive":
                let milliseconds = parts.count > 1 ? Int(parts[1]) ?? 1 : 1
                return .adaptive(threshold: .milliseconds(milliseconds))
            default:
                return .inline
        }
    }

    // MARK: Routes

    /// `GET /exec/trivial` — the smallest possible handler, so the measurement is of the policy.
    private static func trivialRoute() -> Route {
        Route.get("/exec/trivial") { _, _, _ in .text("ok\n") }
    }

    /// `GET /exec/cpu` — approximately 2 ms of real arithmetic on the calling thread.
    private static func cpuRoute() -> Route {
        Route.get("/exec/cpu") { _, _, _ in .text("cpu \(burn(cpuIterations))\n") }
    }

    /// `GET /exec/block` — holds its thread for ``blockingDuration`` without suspending its task.
    private static func blockingRoute() -> Route {
        Route.get("/exec/block") { _, _, _ in
            blockCallingThread()
            return .text("blocked\n")
        }
    }

    /// Blocks the calling thread for ``blockingDuration``.
    ///
    /// Synchronous on purpose. `Thread.sleep` is marked `noasync` precisely so nobody stalls a
    /// concurrency thread by accident, and `Task.sleep` — the replacement it points at — would
    /// suspend the task and free the reactor, which is the one thing this route must NOT do. Routing
    /// it through a non-async function is a deliberate, contained escape: the whole purpose of
    /// `/exec/block` is to model the handler that holds a thread, which is what a synchronous
    /// filesystem read, a compression pass or a public-key verification does to a reactor today.
    private static func blockCallingThread() {
        Thread.sleep(forTimeInterval: blockingDuration)
    }

    // MARK: The workload

    /// Runs `iterations` rounds of an integer mix and returns the accumulator.
    ///
    /// The result is written into the response body so neither the optimizer nor the linker can
    /// discard the loop — a CPU-burn route that got folded away would be the one way this whole
    /// measurement could lie without anyone noticing. The mix is a 64-bit xorshift-and-multiply:
    /// dependent, branch-free, cache-resident, and using only wrapping arithmetic so it cannot trap.
    static func burn(_ iterations: Int) -> UInt64 {
        var state: UInt64 = 0x2545_F491_4F6C_DD1D
        for _ in 0 ..< iterations {
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            state = state &* 0x9E37_79B9_7F4A_7C15
        }
        return state
    }

    /// Prints the measured cost of ``cpuIterations`` and returns, for `HTTPD_EXEC_CALIBRATE=1`.
    ///
    /// Reports the best of several passes rather than a mean: the aim is the machine's capability
    /// with the fewest interruptions, and a mean on a shared host mostly measures the other tenants.
    static func calibrate() {
        var best = Double.greatestFiniteMagnitude
        for _ in 0 ..< 20 {
            let started = ContinuousClock.now
            blackHole(burn(cpuIterations))
            let elapsed = (ContinuousClock.now - started).components
            // Both components, not just the sub-second one: a machine slow enough to cross a second
            // would otherwise report the remainder and read as impossibly fast.
            best = min(
                best,
                Double(elapsed.seconds) * 1_000
                    + Double(elapsed.attoseconds) / 1_000_000_000_000_000
            )
        }
        print("httpd-example: \(cpuIterations) iterations = \(best) ms (best of 20)")
    }

    /// Consumes a value so a caller cannot be optimized away.
    private static func blackHole(_ value: UInt64) {
        if value == 0 {
            print("")  // unreachable for this seed; the optimizer cannot prove that
        }
    }
}
