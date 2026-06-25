//
//  TransportConnectionID.swift
//  HTTPTransport
//
//  The backbone-agnostic connection abstraction. Backbones bridge their native I/O to these async
//  methods; the HTTP engines consume the protocol and never a concrete backbone.
//

/// A stable per-connection identifier (for logging and per-client limits).
public struct TransportConnectionID: Hashable, Sendable {
    /// The underlying identifier value.
    public let rawValue: UInt64

    /// Wraps a raw identifier value.
    public init(_ rawValue: UInt64) {
        self.rawValue = rawValue
    }
}
