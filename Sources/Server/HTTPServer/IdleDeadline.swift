//
//  IdleDeadline.swift
//  HTTPServer
//
//  One named deadline inside a connection's ``DeadlineWheel`` — the HTTP/1.1 serve loop's idle /
//  Slowloris budget (RFC 9112 §9.3), the HTTP/2 consumer's send budget, and each native-streaming
//  relay's producer-pull budget all being the same thing with different escalation.
//
//  This used to be a `Mutex`-backed class with its own watchdog *task* per instance: two per HTTP/2
//  connection plus one per concurrent streaming relay, each polling while disarmed and — the actual
//  defect — unable to be woken when an earlier deadline was armed. It is now a two-word handle into
//  the connection's single wheel, so arming allocates nothing and costs one lock plus a heap sift.
//

/// A named deadline registered in a connection's ``DeadlineWheel``.
///
/// A value type: the identity lives in the wheel, so copying one into a helper (the serve loops pass
/// it down through a dozen frames) shares the same timer rather than forking it.
struct IdleDeadline: Sendable {
    /// The connection's wheel — reachable so HTTP/2 can register its send and relay deadlines in the
    /// same one rather than standing up a second facility.
    let wheel: DeadlineWheel

    private let handle: DeadlineHandle

    /// Registers a deadline in `wheel` that reports through `onLapse` and then escalates as `escalation`
    /// says.
    ///
    /// `onLapse` runs on the watchdog's task and must not block — it flags state the serve loop reads,
    /// or yields into a mailbox.
    init(
        in wheel: DeadlineWheel,
        escalation: DeadlineLapseAction,
        onLapse: (@Sendable () -> Void)? = nil
    ) {
        self.wheel = wheel
        self.handle = wheel.register {
            onLapse?()
            return escalation
        }
    }

    /// Arms the deadline before a blocking receive or send, which must complete by `key` — elapsed
    /// time since the server's epoch, as ``HTTPServer/deadlineKey(after:)`` computes it.
    func arm(_ key: Duration) { wheel.arm(handle, until: key) }

    /// Disarms after the operation returns, so the (fast) processing between them is not timed.
    func disarm() { wheel.disarm(handle) }

    /// Retires the timer for good, so nothing armed for it can fire against a recycled slot.
    func release() { wheel.release(handle) }

    /// Whether the operation ended on a deadline lapse — so the read loop reports a clean idle close
    /// rather than a truncation error.
    var hasLapsed: Bool { wheel.hasLapsed(handle) }
}
