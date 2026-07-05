//
//  HTTP2StreamPermit.swift
//  HTTPServer
//
//  A one-shot, level-triggered "may I pull the next chunk" signal from the HTTP/2 merged-mailbox
//  consumer to a native-streaming relay task (P6b / RFC 9113 §8.1 / §6.9). Only the consumer may read
//  `HTTP2Connection.pendingBacklog(of:)` — the engine is single-owner there, exactly like every other
//  engine mutation — so a relay, which never touches the engine, learns indirectly through this permit
//  that a stream's send-window backlog has drained to zero and it is safe to pull the producer's next
//  chunk without growing that backlog past the 1-chunk-ahead bound the original (single-stream) design
//  relied on. Mirrors ``AsyncHandoff``'s exactly-once continuation idiom: a banked grant for a relay that
//  has not asked yet, a parked continuation for one that has, and cancellation-aware so a relay parked
//  here unwinds promptly when the connection tears down instead of leaking a continuation.
//
//  One consumer + one relay per instance — not a general multi-party primitive.
//

/// A one-shot, level-triggered pull permission from the HTTP/2 consumer to one native-streaming relay.
actor HTTP2StreamPermit {
    private var granted = false
    private var waiter: CheckedContinuation<Void, Never>?

    /// Consumer: grant permission to pull the next chunk.
    ///
    /// Resumes a relay already parked in ``waitForGrant()`` at once; otherwise banks the grant so the
    /// relay's *next* wait returns immediately. Redundant grants collapse (level-triggered, not a
    /// counter) — the consumer calls this after every flush that could have drained the stream's
    /// backlog, whether or not it actually did.
    func grant() {
        if let waiter {
            self.waiter = nil
            waiter.resume()
        }
        else {
            granted = true
        }
    }

    /// Relay: wait for permission — consumes a banked grant at once, else parks until ``grant()``.
    ///
    /// Cancellation-aware (mirrors ``AsyncHandoff/next()``): a relay parked here when the connection
    /// tears down resumes promptly instead of leaking a continuation, so the merged-mailbox consumer's
    /// teardown (`group.cancelAll()`) unwinds this relay too.
    func waitForGrant() async {
        if granted {
            granted = false
            return
        }
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                if Task.isCancelled {
                    continuation.resume()  // already cancelled before we parked
                }
                else {
                    waiter = continuation
                }
            }
        } onCancel: {
            Task { await self.resumeWaiterOnCancel() }
        }
    }

    /// Resumes a relay parked in ``waitForGrant()`` when its task is cancelled (a plain wake, not a
    /// failure signal — the relay's own next `AsyncHandoff.next()` call is what actually observes the
    /// cancellation and unwinds the pump loop).
    ///
    /// A no-op once ``grant()`` has already taken the waiter — actor isolation serializes this against
    /// it, and the nil-out guarantees a single resume.
    private func resumeWaiterOnCancel() {
        guard let waiter else {
            return
        }
        self.waiter = nil
        waiter.resume()
    }
}
