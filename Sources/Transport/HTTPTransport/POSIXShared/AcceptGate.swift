//
//  AcceptGate.swift
//  HTTPTransport
//
//  One admission policy for the five near-identical POSIX accept loops (kqueue, epoll, swift-system,
//  Dispatch, portable TLS). Each loop differs only in how it *suspends* — a one-shot readiness
//  re-arm, a `DispatchSource`, a semaphore — so the decision itself (charge, close on refusal,
//  distinguish "keep draining" from "stop and stay suspended") lives here once, where it can be
//  reasoned about and mutated in a single place.
//
//  Standards: `accept()`/`close()` per POSIX.1-2017 (IEEE Std 1003.1-2017); a resource-exhaustion
//  defense in the spirit of RFC 9110 §15.5.30 (429) — CWE-770, CWE-400.
//

/// The admission decision an accept loop applies to a descriptor it has just accepted (audit F8).
///
/// Charging happens here, between `accept(2)` and the `yield` — never after — so a connection over the
/// ceiling is closed while it is still just a descriptor, and never becomes a queued connection or a
/// serve task.
struct AcceptGate {
    /// The shared ceiling, or `nil` for an ungated listener (benchmarks, the conformance battery).
    let admission: ConnectionAdmission?

    /// What the accept loop must do with the descriptor it just accepted.
    enum Outcome {
        /// Charged: yield the connection carrying this ticket (`nil` when ungated).
        ///
        /// `saturated` marks the admission that consumed the **last** slot: yield it, then stop
        /// draining and stop re-arming until the gate's resume fires.
        case admit(AdmissionTicket?, saturated: Bool)
        /// Over the per-host cap: the descriptor is already closed — **keep draining**, and keep the
        /// accept source armed. Suspending on one abusive source would let it deny service to
        /// everyone else.
        case rejectedContinue
        /// Over the global cap: the descriptor is already closed — stop draining **and** stop
        /// re-arming. The kernel then fills the `listen(2)` backlog and finally refuses SYNs, which is
        /// the backpressure; the gate re-arms the loop at its hysteresis watermark.
        case saturatedStop
    }

    /// Charges a slot for `host`, closing `descriptor` immediately on rejection.
    ///
    /// `close` is injected rather than calling `close(2)` directly because each backbone owns its
    /// descriptor differently — the swift-system loop holds a typed `FileDescriptor`, the event-loop
    /// backbones may want the close serialized on the loop that watches the fd.
    func admit(descriptor: Int32, host: String, close: (Int32) -> Void) -> Outcome {
        guard let admission else {
            return .admit(nil, saturated: false)
        }
        switch admission.admit(host: host) {
            case .admitted(let ticket, let saturated):
                return .admit(ticket, saturated: saturated)
            case .rejectedHost:
                close(descriptor)
                return .rejectedContinue
            case .rejectedTotal:
                close(descriptor)
                return .saturatedStop
        }
    }
}
