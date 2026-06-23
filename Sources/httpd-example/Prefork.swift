//
//  Prefork.swift
//  httpd-example
//
//  A tiny, trap-free prefork supervisor (the multi-process crash-defense + parallelism model).
//
//  The master `posix_spawn`s N *fresh* copies of this binary as workers (fork+exec atomically, so the
//  multi-threaded runtime is never an issue); each worker re-runs the server with SO_REUSEPORT so the
//  kernel load-balances accepted connections across them — one process per core, true multi-core
//  scaling. The master then only supervises: it `waitpid`s, and respawns a crashed worker (with
//  exponential backoff against a crash loop). Because a worker is a separate process, an *uncatchable*
//  trap in application code — a force-unwrap, an OOM kill, a deadlock — takes down only that worker;
//  the master respawns it and the server keeps serving. This is the one part of crash defense an
//  in-process design cannot provide.
//
//  The worker marker (HTTPD_WORKER=1) is set ONCE in the parent before spawning and carried to each
//  child via the inherited `environ`. POSIX-only by nature (Network.framework cannot share a listener
//  across processes the way SO_REUSEPORT does).
//

import Darwin
import Dispatch
import Foundation

/// A minimal fork/exec prefork supervisor for the POSIX backbones.
enum Prefork {

    /// The requested worker count (`HTTPD_WORKERS`), if this process should become a prefork master.
    static var workerCount: Int? {
        guard let raw = ProcessInfo.processInfo.environment["HTTPD_WORKERS"],
            let count = Int(raw), count > 0
        else { return nil }
        return count
    }

    /// Whether this process is a spawned worker (the master sets `HTTPD_WORKER=1` before forking).
    static var isWorker: Bool {
        ProcessInfo.processInfo.environment["HTTPD_WORKER"] == "1"
    }

    /// Becomes the prefork master: spawns `workers` worker processes, then supervises them forever.
    ///
    /// Respawns a crashed worker with exponential backoff (a crash-loop guard). Never returns.
    static func supervise(workers: Int) -> Never {
        // Children inherit this via fork(); execv() carries `environ`, so each worker sees it. Set
        // ONCE here in the parent (where it is safe), never between fork() and execv().
        setenv("HTTPD_WORKER", "1", 1)
        installShutdownForwarding()

        var spawnedAt: [pid_t: UInt64] = [:]
        var consecutiveFastDeaths = 0
        for _ in 0..<workers {
            let pid = spawnWorker()
            spawnedAt[pid] = DispatchTime.now().uptimeNanoseconds
        }
        let pids = spawnedAt.keys.sorted().map(String.init).joined(separator: " ")
        log("master \(getpid()) supervising \(workers) workers: \(pids)")

        while true {
            var status: Int32 = 0
            let dead = waitpid(-1, &status, 0)
            guard dead > 0 else { continue }  // EINTR (a signal) or no children — retry
            let livedNanos = DispatchTime.now().uptimeNanoseconds - (spawnedAt[dead] ?? 0)
            spawnedAt[dead] = nil
            // Crash-loop guard: back off only when a worker dies within a second of spawning.
            if livedNanos < 1_000_000_000 {
                consecutiveFastDeaths += 1
                let backoffMillis = min(100 << min(consecutiveFastDeaths, 6), 5_000)  // cap 5s
                usleep(UInt32(backoffMillis) * 1_000)
            } else {
                consecutiveFastDeaths = 0
            }
            let pid = spawnWorker()
            spawnedAt[pid] = DispatchTime.now().uptimeNanoseconds
            log("worker \(dead) exited (status \(status)); respawned as \(pid)")
        }
    }

    /// Spawns a fresh copy of this binary as a worker process, returning its pid (or `-1` on failure).
    ///
    /// Uses `posix_spawn` (fork+exec, atomically), passing the current `environ` — which already
    /// carries `HTTPD_WORKER=1`, set once in the parent.
    private static func spawnWorker() -> pid_t {
        guard let path = CommandLine.unsafeArgv[0] else { return -1 }
        var pid: pid_t = 0
        let result = posix_spawn(&pid, path, nil, nil, CommandLine.unsafeArgv, environ)
        return result == 0 ? pid : -1
    }

    /// On SIGTERM/SIGINT, terminates the whole worker group (and the master) at once.
    ///
    /// The master first moves itself + its workers into their own process group, then the handler
    /// resets the signal to default and `killpg`s that group — so every worker dies with the master
    /// instead of being orphaned. (Doing it in the handler, not via a flag, sidesteps BSD `signal()`'s
    /// `SA_RESTART`, which would auto-restart the master's blocking `waitpid` and never re-check.)
    private static func installShutdownForwarding() {
        setpgid(0, 0)  // isolate master + workers so killpg targets only them
        let terminate: @convention(c) (Int32) -> Void = { signum in
            signal(signum, SIG_DFL)
            killpg(0, SIGTERM)
        }
        signal(SIGTERM, terminate)
        signal(SIGINT, terminate)
    }

    private static func log(_ message: String) {
        FileHandle.standardError.write(Data("prefork: \(message)\n".utf8))
    }
}
