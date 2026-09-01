//
//  AdmissionTicket.swift
//  HTTPTransport
//
//  The receipt for one charged connection slot (audit F8). A ticket — rather than a bare counter the
//  caller must remember to decrement — is what makes a leaked slot structurally impossible: a
//  connection can be yielded into the accept stream and then dropped (stream termination, a shutdown
//  race, a serve task that never starts), and the ticket's `deinit` still returns the slot.
//
//  Standards: part of the resource-exhaustion defense in the spirit of RFC 9110 §15.5.30 (429) —
//  CWE-770 (allocation of resources without limits), CWE-400 (uncontrolled resource consumption).
//

internal import Synchronization

/// A charged connection slot, released exactly once — on ``release()`` or defensively on `deinit`.
///
/// A ``ConnectionAdmission`` hands one of these out for every admitted connection. The transport
/// attaches it to the connection it yields; the server holds it for the connection's serve loop and
/// releases it when the loop ends. Because `deinit` releases too, a connection dropped anywhere in
/// between — never dequeued from the accept stream, never served — cannot leak its slot, which is what
/// makes the ceiling genuinely cover *queued and handshaking* connections rather than only served ones.
///
/// Release is idempotent and thread-safe: an explicit ``release()`` followed by deallocation returns
/// the slot once, never twice (a double release would hand a live connection's slot to a second peer).
public final class AdmissionTicket: Sendable, Equatable {
    /// The gate this slot was charged against, held strongly so a ticket outliving its server still
    /// releases into a valid gate.
    private let admission: ConnectionAdmission
    /// The per-host bucket to credit back — captured at admit time, because the peer address is not
    /// reachable from the ticket and must not be re-derived (a mismatched key would corrupt the map).
    private let host: String
    /// Guards the release against running twice (explicit release, then `deinit`).
    private let isReleased = Atomic<Bool>(false)

    /// Creates a ticket for a slot already charged on `admission` for `host`.
    ///
    /// Only ``ConnectionAdmission/admit(host:)`` constructs these: the slot must already be charged,
    /// otherwise the release would credit back a slot that was never taken.
    init(admission: ConnectionAdmission, host: String) {
        self.admission = admission
        self.host = host
    }

    deinit {
        // The defensive half of the contract: a connection dropped without ever being served — the
        // accept stream terminated, the serve task cancelled before it started — still returns its slot.
        release()
    }

    /// Returns this slot to the gate, at most once.
    ///
    /// Safe to call from any thread and any number of times; the first call wins and every later one
    /// (including the `deinit`) is a no-op. Calling it explicitly at the end of a serve loop frees the
    /// slot promptly rather than waiting on the last reference to drop.
    public func release() {
        guard !isReleased.exchange(true, ordering: .acquiringAndReleasing) else {
            return
        }
        admission.release(host: host)
    }

    /// Two tickets are the same ticket only when they are the same object — a slot has identity, not a
    /// value.
    public static func == (lhs: AdmissionTicket, rhs: AdmissionTicket) -> Bool {
        lhs === rhs
    }
}
