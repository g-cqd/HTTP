//
//  ConnectionAdmissionTests.swift
//  HTTPTransportTests
//
//  The shared connection-admission gate (audit F8). The gate is the *only* thing standing between an
//  accept flood and unbounded queued connections / serve tasks, so its arithmetic is pinned here:
//  the total and per-host ceilings, the saturation edge that tells a transport to stop re-arming, the
//  hysteresis watermark that tells it when to re-arm again, and the ticket whose `deinit` makes a
//  leaked slot structurally impossible.
//
//  Standards: a resource-exhaustion defense in the spirit of RFC 9110 §15.5.30 (429) — CWE-770
//  (allocation of resources without limits) and CWE-400 (uncontrolled resource consumption).
//

import HTTPTestSupport
import Synchronization
import Testing

@testable import HTTPTransport

@Suite("Connection admission — the pre-task gate (audit F8)")
struct ConnectionAdmissionTests {
    /// A `Sendable` tally of resume callbacks — the gate invokes them after dropping its lock, from
    /// whichever thread released the last slot.
    private final class Counter: Sendable {
        private let tally = Mutex<Int>(0)

        var value: Int { tally.withLock(\.self) }

        func increment() {
            tally.withLock { $0 += 1 }
        }

        deinit {
            // No teardown beyond ARC.
        }
    }

    private static func makeGate(
        total: Int,
        perHost: Int = .max,
        resumeRatio: Double = 0.875
    ) -> ConnectionAdmission {
        ConnectionAdmission(
            capacity: ConnectionAdmission.Capacity(
                total: total,
                perHost: perHost,
                resumeRatio: resumeRatio
            )
        )
    }

    @Test("admits exactly `total` slots and rejects every one beyond it", arguments: [1, 2, 4, 16])
    func admitsUpToTotalThenRejects(_ total: Int) {
        let gate = Self.makeGate(total: total)
        var tickets: [AdmissionTicket] = []
        for _ in 0 ..< total {
            guard case .admitted(let ticket, _) = gate.admit(host: "10.0.0.1") else {
                Issue.record("the gate rejected a connection below its \(total)-slot ceiling")
                return
            }
            tickets.append(ticket)
        }
        #expect(gate.counts.total == total)
        // Three more attempts, all beyond the ceiling: every one is a *global* rejection, which is
        // what tells a transport to suspend its accept source rather than keep draining.
        for _ in 0 ..< 3 {
            #expect(gate.admit(host: "10.0.0.1") == .rejectedTotal)
        }
        #expect(gate.counts.total == total)
        tickets.removeAll()
        #expect(gate.counts == (total: 0, hosts: 0))
    }

    @Test("a per-host rejection does NOT report saturation, and other hosts are still admitted")
    func perHostRejectionKeepsTheListenerDraining() {
        // The global ceiling is far away; only the per-host one binds. Were a per-host rejection to
        // suspend the listener, one abusive source would deny service to every other client.
        let gate = Self.makeGate(total: 64, perHost: 2)
        var noisy: [AdmissionTicket] = []
        for _ in 0 ..< 2 {
            guard case .admitted(let ticket, let saturated) = gate.admit(host: "10.0.0.1") else {
                Issue.record("the gate rejected a connection below the per-host cap")
                return
            }
            #expect(!saturated, "the per-host cap must never report global saturation")
            noisy.append(ticket)
        }
        #expect(gate.admit(host: "10.0.0.1") == .rejectedHost)
        #expect(!gate.isSaturated, "a per-host rejection must not suspend the accept source")
        // A different host is unaffected — the abusive peer has not denied service to anyone else.
        guard case .admitted(let other, _) = gate.admit(host: "10.0.0.2") else {
            Issue.record("a second host was refused because a first host hit its per-host cap")
            return
        }
        #expect(gate.counts == (total: 3, hosts: 2))
        noisy.removeAll()
        #expect(gate.counts == (total: 1, hosts: 1))
        other.release()
        #expect(gate.counts == (total: 0, hosts: 0))
    }

    @Test("saturation is reported once, and resume fires at the watermark — not on every release")
    func saturationEdgeAndHysteresis() {
        // total 16, ratio 0.875 → the watermark is 14: the accept source re-arms only once the live
        // count falls back to 14, so a server sitting at the ceiling does not suspend/re-arm (a
        // kevent/epoll_ctl syscall) on every single connection close.
        let gate = Self.makeGate(total: 16, resumeRatio: 0.875)
        let resumes = Counter()
        gate.onResume { resumes.increment() }

        var tickets: [AdmissionTicket] = []
        var saturations = 0
        for _ in 0 ..< 16 {
            guard case .admitted(let ticket, let saturated) = gate.admit(host: "10.0.0.1") else {
                Issue.record("the gate rejected a connection below its 16-slot ceiling")
                return
            }
            if saturated {
                saturations += 1
            }
            tickets.append(ticket)
        }
        #expect(saturations == 1, "saturation must be an edge, reported exactly once")
        #expect(gate.isSaturated)
        // A further rejection while saturated must not re-report the edge.
        #expect(gate.admit(host: "10.0.0.1") == .rejectedTotal)
        #expect(resumes.value == 0)

        tickets.removeLast().release()  // 15 live — still above the watermark
        #expect(resumes.value == 0, "resume must not fire on every release")
        tickets.removeLast().release()  // 14 live — the watermark: re-arm exactly here
        #expect(resumes.value == 1)
        #expect(!gate.isSaturated)
        tickets.removeLast().release()  // 13 live — already re-armed, no second resume
        tickets.removeLast().release()  // 12 live
        #expect(resumes.value == 1, "resume fires once per suspend/resume cycle")
    }

    @Test("a ticket dropped without ever being served releases its slot on deinit")
    func droppedTicketReleasesOnDeinit() {
        // A connection can be yielded into the accept stream and then dropped — stream termination, a
        // shutdown race, a serve task that never starts. The ticket's `deinit` makes that leak
        // structurally impossible, which is what makes "the cap covers queued connections" a property
        // of the type rather than an assertion about call sites.
        let gate = Self.makeGate(total: 2)
        do {
            guard case .admitted = gate.admit(host: "10.0.0.1") else {
                Issue.record("the gate rejected the first connection")
                return
            }
            // The ticket is dropped at the end of this statement — never released explicitly.
        }
        #expect(gate.counts == (total: 0, hosts: 0))
        // The slot really is reusable: two more connections fit under the 2-slot ceiling.
        guard case .admitted(let first, _) = gate.admit(host: "10.0.0.1"),
            case .admitted(let second, _) = gate.admit(host: "10.0.0.1")
        else {
            Issue.record("the dropped ticket did not free its slot")
            return
        }
        #expect(gate.admit(host: "10.0.0.1") == .rejectedTotal)
        first.release()
        second.release()
        #expect(gate.counts == (total: 0, hosts: 0))
    }

    @Test("an explicit release is idempotent — a released ticket's deinit does not double-free")
    func releaseIsIdempotent() {
        let gate = Self.makeGate(total: 4)
        guard case .admitted(let ticket, _) = gate.admit(host: "10.0.0.1") else {
            Issue.record("the gate rejected the first connection")
            return
        }
        ticket.release()
        ticket.release()
        #expect(gate.counts == (total: 0, hosts: 0))
        // A second connection must still fit: a double release would have driven the count negative
        // (or, worse, freed a slot another connection is holding).
        guard case .admitted = gate.admit(host: "10.0.0.1") else {
            Issue.record("the gate leaked a slot across a double release")
            return
        }
    }

    @Test("admit/release allocate only the ticket itself on the hit path")
    func hitPathAllocatesOnlyTheTicket() {
        guard let baseline = Self.ticketShapedBaseline() else {
            return  // counting is Darwin-only; the oracle is a no-op elsewhere
        }
        let gate = Self.makeGate(total: 16)
        let host = "10.0.0.1"
        let cycle: () -> Void = {
            guard case .admitted(let ticket, _) = gate.admit(host: host) else {
                return
            }
            ticket.release()
        }
        for _ in 0 ..< Self.hitPathPairs {
            cycle()  // warm the per-host map's storage and any one-time lazy initialization
        }
        // The budget is calibrated in the same run against `hitPathPairs` bare allocations of a
        // ticket-shaped object, so it measures the gate rather than the allocator's bookkeeping: a
        // charge/release pair may cost the ticket and NOTHING else — no per-host map growth, no
        // copy-on-write of the counts, no boxing of the host key or the decision.
        expectAllocations(noMoreThan: baseline) {
            for _ in 0 ..< Self.hitPathPairs {
                cycle()
            }
        }
    }

    /// The number of warmed charge/release pairs the hit-path allocation guard measures.
    private static let hitPathPairs = 10_000

    /// A stand-in with the same storage shape as an admission ticket.
    ///
    /// A reference plus a retained string, so allocating one costs exactly what allocating an
    /// ``AdmissionTicket`` costs.
    private final class TicketShaped {
        let gate: ConnectionAdmission
        let host: String

        init(gate: ConnectionAdmission, host: String) {
            self.gate = gate
            self.host = host
        }

        deinit {
            // No teardown beyond ARC.
        }
    }

    /// Measures ``hitPathPairs`` bare ticket-shaped allocations, or `nil` where counting is
    /// unavailable — the calibration the hit-path guard budgets against.
    private static func ticketShapedBaseline() -> Int? {
        let gate = makeGate(total: 16)
        let host = "10.0.0.1"
        var sink: TicketShaped?
        for _ in 0 ..< 1_000 {
            sink = TicketShaped(gate: gate, host: host)
        }
        let measured = mallocDelta {
            for _ in 0 ..< hitPathPairs {
                sink = TicketShaped(gate: gate, host: host)
            }
        }
        _ = sink
        return measured
    }
}
