//
//  AsyncEventProbeTimeoutError.swift
//  HTTPTestSupport
//
//  The error an ``AsyncEventProbe`` raises when its suspend-until-count boundary is not reached
//  before the (clock-driven) timeout — carrying the probe's creation site so a hung test points at
//  the probe rather than at the timeout machinery.
//

public import Testing

/// Raised when an ``AsyncEventProbe/wait(forAtLeast:within:clock:)`` boundary is not reached before
/// its (clock-driven) timeout.
///
/// Carries the probe's *creation* site, so a hung test points at the probe rather than at the timeout
/// machinery.
public struct AsyncEventProbeTimeoutError: Error, CustomStringConvertible {
    /// The number of events the wait required.
    public let requested: Int
    /// The number of events recorded when the timeout fired.
    public let recorded: Int
    /// The source location where the probe was created.
    public let creation: SourceLocation

    /// A human-readable description naming the shortfall and the probe's creation site.
    public var description: String {
        "AsyncEventProbe timed out waiting for at least \(requested) event(s); only \(recorded) recorded. "
            + "Probe created at \(creation)."
    }
}
