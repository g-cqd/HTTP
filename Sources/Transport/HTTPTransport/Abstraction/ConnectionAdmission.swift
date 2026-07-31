//
//  ConnectionAdmission.swift
//  HTTPTransport
//
//  The synchronous connection-admission gate shared by every backbone and by the server (audit F8).
//  It used to live in `HTTPServer` and ran *after* the serve task had already been created, so the
//  count was "accepted and task-spawned", not "accepted": under an accept flood the queue of yielded
//  connections and the task group both grew before the nominal ceiling was ever consulted. Moving it
//  down to the transport layer lets a slot be charged before `yield` — before any task exists — and
//  lets a saturated transport stop re-arming its accept source instead of accepting into a backlog.
//
//  Standards: a resource-exhaustion defense in the spirit of RFC 9110 §15.5.30 (429) — CWE-770
//  (allocation of resources without limits), CWE-400 (uncontrolled resource consumption).
//

internal import Synchronization

/// A hard ceiling on connections that are accepted, queued, handshaking, or actively served, charged
/// **before** any task is created (audit F8).
///
/// One gate is shared by the server and its transport. A backbone charges a slot the instant
/// `accept(2)` (or the Network.framework equivalent) hands it a descriptor and *before* it yields the
/// connection, so the accept stream's depth can never exceed ``Capacity/total``; the server adopts the
/// resulting ``AdmissionTicket`` and releases it when the serve loop ends.
///
/// Three properties are worth stating explicitly, because each is easy to "simplify" away:
///
/// - **Hysteresis is not decoration.** A server sitting exactly at the ceiling would otherwise suspend
///   and re-arm its accept source on *every single close* — a `kevent`/`epoll_ctl` syscall storm at
///   precisely the moment the machine can least afford it. The gate suspends at 100 % and only signals
///   a resume once the live count falls back to ``Capacity/resumeRatio`` of the ceiling.
/// - **A ticket, not a bare counter.** See ``AdmissionTicket``: a slot returned by `deinit` is what
///   makes "the cap covers queued and handshaking connections" fall out of the type rather than being
///   asserted about call sites.
/// - **A per-host rejection must not suspend the listener.** Only a *global* rejection
///   (``Decision/rejectedTotal``) reports saturation; a ``Decision/rejectedHost`` leaves the accept
///   source draining, because suspending on one abusive source would let it deny service to everyone.
///
/// Thread-safe and synchronous: one `Mutex` guards the counts, and the registered resume closure is
/// invoked *after* the lock is dropped (a re-arm may take a syscall, and must never run under it).
public final class ConnectionAdmission: Sendable {
    /// The ceilings a gate enforces, plus the hysteresis ratio it re-arms at.
    public struct Capacity: Sendable, Equatable {
        /// The global ceiling on live connections (`HTTPLimits.maxConnections`).
        public var total: Int
        /// The ceiling on live connections from one peer host (`HTTPLimits.maxConnectionsPerClient`).
        public var perHost: Int
        /// The fraction of ``total`` the live count must fall back to before a saturated accept source
        /// re-arms (`HTTPLimits.acceptResumeRatio`); clamped to `0...1`.
        public var resumeRatio: Double

        /// Creates a capacity from the global and per-host ceilings.
        public init(total: Int, perHost: Int, resumeRatio: Double = 0.875) {
            self.total = total
            self.perHost = perHost
            self.resumeRatio = resumeRatio
        }
    }

    /// The outcome of charging one slot.
    public enum Decision: Sendable, Equatable {
        /// A slot was charged. `saturated` is `true` only on the *edge* into saturation — the caller
        /// must yield this connection and then stop re-arming its accept source.
        case admitted(AdmissionTicket, saturated: Bool)
        /// The global ceiling is full: close the connection **and** suspend the accept source.
        case rejectedTotal
        /// This peer's ceiling is full: close the connection but **keep draining** — suspending here
        /// would let one abusive source deny service to every other client.
        case rejectedHost
    }

    /// The ceilings this gate enforces.
    public let capacity: Capacity

    /// The live-count value at or below which a saturated accept source re-arms.
    ///
    /// `total * ratio`, rounded down and precomputed, so the release path does no floating-point work
    /// under the lock.
    private let resumeWatermark: Int
    private let state = Mutex<Counts>(Counts())
    /// The transport's accept re-arm, invoked once (per saturation cycle) after the lock is dropped.
    private let resumeHandler = Mutex<(@Sendable () -> Void)?>(nil)

    /// The live accounting: a global total, per-host counts, and the latched saturation flag.
    private struct Counts {
        var total = 0
        var perHost: [String: Int] = [:]
        /// Latched when the ceiling is reached, cleared at the watermark — the hysteresis state.
        var isSaturated = false
    }

    /// What charging a slot did, decided under the lock; the ticket is built outside it.
    private enum Charge {
        case charged(saturated: Bool)
        case rejectedTotal
        case rejectedHost
    }

    /// Creates a gate enforcing `capacity`.
    public init(capacity: Capacity) {
        self.capacity = capacity
        let ratio = min(max(capacity.resumeRatio, 0), 1)
        self.resumeWatermark = max(0, Int((Double(capacity.total) * ratio).rounded(.down)))
    }

    deinit {
        // No teardown beyond ARC; outstanding tickets hold this object alive until they release.
    }

    /// Charges one slot for `host`, returning the ticket that owns it or the reason it was refused.
    ///
    /// Synchronous and lock-only — no `await`, no I/O — so a caller can charge on an event-loop thread
    /// or inside a Network.framework callback before it yields anything. The only allocation is the
    /// returned ``AdmissionTicket``; the counts are mutated in place under the lock.
    public func admit(host: String) -> Decision {
        switch chargeSlot(host: host) {
            case .charged(let saturated):
                return .admitted(
                    AdmissionTicket(admission: self, host: host),
                    saturated: saturated
                )
            case .rejectedTotal:
                return .rejectedTotal
            case .rejectedHost:
                return .rejectedHost
        }
    }

    /// Registers the transport's accept re-arm, invoked once the live count falls back to the
    /// hysteresis watermark.
    ///
    /// Exactly one closure is held (a later call replaces it): a gate belongs to one server, and one
    /// server drives one accept source. It runs on whichever thread released the deciding slot, with
    /// the gate's lock **not** held, so it is free to make the `kevent`/`epoll_ctl`/`resume` syscall.
    public func onResume(_ resume: @escaping @Sendable () -> Void) {
        resumeHandler.withLock { $0 = resume }
    }

    /// The live connection total and the number of distinct hosts holding at least one slot.
    public var counts: (total: Int, hosts: Int) {
        state.withLock { ($0.total, $0.perHost.count) }
    }

    /// Whether the gate is currently latched at its ceiling — the accept source should be suspended.
    ///
    /// Latched by the admission that consumes the last slot (or by the first global rejection) and
    /// cleared at the hysteresis watermark. A blocking accept loop, which has no readiness source to
    /// suspend, polls this to decide whether to park.
    public var isSaturated: Bool {
        state.withLock(\.isSaturated)
    }

    // MARK: - Internals

    /// Charges a slot under the lock, returning what happened (the ticket is built by the caller so
    /// the critical section holds no allocation).
    private func chargeSlot(host: String) -> Charge {
        state.withLock { counts in
            guard counts.total < capacity.total else {
                counts.isSaturated = true  // a global rejection always means "suspend"
                return .rejectedTotal
            }
            let current = counts.perHost[host, default: 0]
            guard current < capacity.perHost else {
                return .rejectedHost  // deliberately NOT a saturation: keep draining
            }
            counts.perHost[host] = current + 1
            counts.total += 1
            // Edge-triggered: only the admission that *reaches* the ceiling reports saturation, so a
            // transport suspends once per cycle instead of on every admission at the ceiling.
            let edge = counts.total >= capacity.total && !counts.isSaturated
            if edge {
                counts.isSaturated = true
            }
            return .charged(saturated: edge)
        }
    }

    /// Returns one slot for `host` and, on the hysteresis edge, invokes the registered resume.
    ///
    /// Called only by ``AdmissionTicket/release()``, which guarantees it runs at most once per slot.
    func release(host: String) {
        let shouldResume = state.withLock { counts -> Bool in
            guard counts.total > 0 else {
                return false
            }
            counts.total -= 1
            if let current = counts.perHost[host], current > 1 {
                counts.perHost[host] = current - 1
            }
            else {
                // Drop the key rather than leaving a zero: the map is keyed by attacker-chosen peer
                // addresses, so a lingering entry per address is itself unbounded growth (CWE-770).
                counts.perHost[host] = nil
            }
            guard counts.isSaturated, counts.total <= resumeWatermark else {
                return false
            }
            counts.isSaturated = false
            return true
        }
        guard shouldResume else {
            return
        }
        // Outside the lock: the re-arm is a syscall on the transport's accept source, and holding the
        // admission lock across it would serialize every concurrent close behind that syscall.
        resumeHandler.withLock(\.self)?()
    }
}
