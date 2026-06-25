//
//  HTTP2Connection+AbuseBudget.swift
//  HTTP2
//
//  RFC 9113 — the time-windowed abuse budget shared by the reset and control-frame floods. Each cap is
//  a *rate* over `streamResetInterval` (decayed via the injected monotonic clock), not a per-connection
//  total, and a server-*emitted* RST_STREAM is charged the same as a client-sent one — so an attacker
//  cannot bypass the Rapid-Reset defense (CVE-2023-44487) by provoking resets the client never sends:
//  MadeYouReset (CVE-2025-8671).
//

internal import HTTPConcurrency
internal import HTTPCore

extension HTTP2Connection {
    /// Charges one cheap control-plane frame against the flood budget.
    ///
    /// Fails closed if a peer floods frames that are cheap to send but do no useful work — PING /
    /// SETTINGS (and ACKs), PRIORITY, zero-length non-final DATA, WINDOW_UPDATE on a closed stream
    /// (RFC 9113 §6.5 / §6.7; CVE-2019-9513 / CVE-2019-9518). Bounded by its own
    /// ``HTTPLimits/maxControlFramesPerInterval`` knob.
    mutating func chargeControlFrame() throws(HTTP2Error) {
        decayBudgetsIfElapsed()
        controlFrameBudget += 1
        guard controlFrameBudget <= limits.maxControlFramesPerInterval else {
            throw .connection(.enhanceYourCalm, "excessive cheap control-plane frames")
        }
    }

    /// Charges one stream reset against the rolling budget — whether the peer sent RST_STREAM or the
    /// engine emitted one for a stream-scoped violation — tripping ENHANCE_YOUR_CALM past the cap
    /// (Rapid Reset CVE-2023-44487 / MadeYouReset CVE-2025-8671).
    mutating func chargeStreamReset() throws(HTTP2Error) {
        decayBudgetsIfElapsed()
        activeStreamResets += 1
        guard activeStreamResets <= limits.maxStreamResetsPerInterval else {
            throw .connection(
                .enhanceYourCalm,
                "excessive stream resets (Rapid Reset / MadeYouReset)"
            )
        }
    }

    /// Resets the abuse budgets once the rolling window has elapsed, so each cap is a rate over
    /// `streamResetInterval` rather than a monotonic per-connection total — fixing both the long-window
    /// bypass and the false positive on a legitimately long-lived connection.
    private mutating func decayBudgetsIfElapsed() {
        guard budgetWindow.rolledOver(at: now()) else {
            return
        }
        activeStreamResets = 0
        controlFrameBudget = 0
    }
}
