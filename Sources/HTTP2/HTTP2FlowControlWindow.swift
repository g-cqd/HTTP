//
//  HTTP2FlowControlWindow.swift
//  HTTP2
//
//  RFC 9113 §5.2 / §6.9 — a single flow-control window. DATA is the only flow-controlled frame; a
//  sender may transmit only as many octets as the window allows, and the receiver replenishes it with
//  WINDOW_UPDATE. The window is a signed quantity (it can go negative after SETTINGS_INITIAL_WINDOW_
//  SIZE shrinks an in-flight stream, §6.9.2) but must never exceed 2^31-1 (§6.9.1). This type holds
//  the arithmetic; the engine scopes any violation to the connection or a stream.
//

/// One HTTP/2 flow-control window (RFC 9113 §5.2 / §6.9) — pure arithmetic, scope-agnostic.
public struct HTTP2FlowControlWindow: Sendable, Equatable {
    /// The maximum window value, 2^31-1 (RFC 9113 §6.9.1).
    public static let maxSize = Int(Int32.max)

    /// The current window.
    ///
    /// May be negative after a SETTINGS-driven shrink (RFC 9113 §6.9.2).
    public private(set) var size: Int

    /// Creates a window at `initialSize` (typically SETTINGS_INITIAL_WINDOW_SIZE, default 65,535).
    public init(initialSize: Int = 65_535) {
        self.size = initialSize
    }

    /// The number of octets that may be sent right now (never negative).
    public var available: Int { max(0, size) }

    /// Reserves up to `requested` octets for sending DATA, returning how many the window grants.
    ///
    /// Sending is partial when the window is smaller than the request; a non-positive window grants 0.
    public mutating func reserve(_ requested: Int) -> Int {
        let granted = min(max(0, requested), available)
        size -= granted
        return granted
    }

    /// The result of applying a window increment (RFC 9113 §6.9 / §6.9.1).
    public enum UpdateOutcome: Sendable, Equatable {
        /// The increment was applied.
        case applied

        /// The increment was 0 — a PROTOCOL_ERROR for WINDOW_UPDATE (§6.9).
        case zeroIncrement

        /// The increment would push the window past 2^31-1 — a FLOW_CONTROL_ERROR (§6.9.1).
        case overflow
    }

    /// Applies a WINDOW_UPDATE increment of `delta` octets (RFC 9113 §6.9).
    ///
    /// A zero increment and an increment that would exceed 2^31-1 are reported for the caller to scope
    /// (PROTOCOL_ERROR and FLOW_CONTROL_ERROR respectively).
    public mutating func increase(by delta: Int) -> UpdateOutcome {
        guard delta != 0 else {
            return .zeroIncrement
        }
        guard delta <= Self.maxSize - size else {
            return .overflow
        }
        size += delta
        return .applied
    }

    /// Shifts the window by `delta` when SETTINGS_INITIAL_WINDOW_SIZE changes (RFC 9113 §6.9.2).
    ///
    /// A positive change that would exceed 2^31-1 is a FLOW_CONTROL_ERROR; a negative change may drive
    /// the window negative, which is valid and throttles the sender until it recovers.
    public mutating func shiftInitial(by delta: Int) -> UpdateOutcome {
        guard delta <= Self.maxSize - size else {
            return .overflow
        }
        size += delta
        return .applied
    }
}
