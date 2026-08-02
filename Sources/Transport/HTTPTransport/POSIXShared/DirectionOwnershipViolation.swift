//
//  DirectionOwnershipViolation.swift
//  HTTPTransport
//
//  The failure a raw connection raises when a second operation reaches a stream direction its sole
//  owner has not finished with. It exists so the ownership contract can FAIL rather than hang.
//
//  What it replaces: `OnceResumer.reset` installed each new continuation over the pending one with a
//  plain assignment. The displaced continuation was then resumed by nothing — not by readiness, which
//  had handed its result to the survivor, and not by close, which finds only the survivor — so the
//  task stayed suspended for the life of the process (CWE-833, deadlock by lost wakeup). Silence is
//  the one outcome not available to a contract violation; either the operations are ordered or the
//  second one is told, immediately, that it may not proceed.
//
//  Standards: TCP carries exactly one sequence space per direction (RFC 9293 §3.1), so a raw byte
//  stream admits exactly one operation owner per direction. Request concurrency belongs above this
//  seam — HTTP/2 stream multiplexing (RFC 9113 §5), HTTP/3 over QUIC streams (RFC 9114 §2).
//

/// A second operation reached a stream direction whose sole owner had not finished.
///
/// Not reachable while a ``DirectionOwner`` gates the direction — the exclusion queues the second
/// caller rather than letting it in. This is the guard rail *under* that exclusion, and the reason the
/// ownership contract is enforced rather than described: remove the exclusion and the next collision
/// throws here on the intruder's very next operation, instead of stranding a task forever.
public struct DirectionOwnershipViolation: Error, Equatable, Sendable {
    /// Creates the violation.
    public init() {
        // No payload: the direction and the connection are already in the caller's stack trace, and a
        // description would be the only thing to compare in a test.
    }
}
