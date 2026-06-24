//
//  HTTP3Settings.swift
//  HTTP3
//
//  RFC 9114 §7.2.4 — the HTTP/3 SETTINGS frame conveys configuration as a sequence of (Identifier,
//  Value) pairs, each a variable-length integer. This models the known parameters (§7.2.4.2 / RFC 9204
//  §5 / RFC 9220), parses a received payload, and serializes one to send. Per §7.2.4.1, identifiers
//  reserved from HTTP/2 (0x02/0x03/0x04/0x05) and any duplicate identifier are a connection error of
//  type H3_SETTINGS_ERROR; unknown identifiers are ignored. A structurally malformed payload (a
//  truncated pair) is H3_FRAME_ERROR.
//

internal import HTTPCore

/// The set of known HTTP/3 SETTINGS parameters, with the v1 defaults (RFC 9114 §7.2.4).
public struct HTTP3Settings: Sendable, Equatable {
    /// QPACK dynamic table capacity in octets — 0 in v1 (the dynamic table is disabled, RFC 9204 §3.2.2).
    public var qpackMaxTableCapacity = 0
    /// QPACK blocked-streams bound — 0 in v1 (no blocked streams without a dynamic table, RFC 9204 §5).
    public var qpackBlockedStreams = 0
    /// Advisory maximum decoded field-section size in octets, or `nil` for unset.
    public var maxFieldSectionSize: Int?
    /// Whether Extended CONNECT is permitted (RFC 9220) — `false` in v1 (WebSocket-over-h3 deferred).
    public var enableConnectProtocol = false

    /// Creates a settings set at the v1 defaults (QPACK table + blocked streams 0).
    public init() {
        // No-op: all stored properties use their declared v1 defaults.
    }

    /// Applies a received SETTINGS payload, updating the known parameters (RFC 9114 §7.2.4).
    ///
    /// Rejects the HTTP/2-reserved identifiers and any duplicate with `H3_SETTINGS_ERROR`; a truncated
    /// (Identifier, Value) pair is `H3_FRAME_ERROR`; unknown identifiers are ignored.
    public mutating func apply(_ payload: RawSpan) throws(HTTP3Error) {
        var reader = ByteReader(payload)
        var seen = Set<UInt64>()
        while !reader.isAtEnd {
            guard let identifier = QUICVarint.decode(&reader) else {
                throw .connection(.h3FrameError, "truncated SETTINGS identifier")
            }
            guard let value = QUICVarint.decode(&reader) else {
                throw .connection(.h3FrameError, "truncated SETTINGS value")
            }
            guard seen.insert(identifier).inserted else {
                throw .connection(.h3SettingsError, "duplicate setting identifier")
            }
            try applyParameter(identifier: identifier, value: value)
        }
    }

    /// Validates and stores one parameter; reserved HTTP/2 ids fail, unknown ids are ignored (§7.2.4.1).
    private mutating func applyParameter(identifier: UInt64, value: UInt64) throws(HTTP3Error) {
        guard !(0x02 ... 0x05).contains(identifier) else {
            throw .connection(.h3SettingsError, "reserved HTTP/2 setting identifier")
        }
        // RFC 9114 §7.2.4 places no upper bound on these advisory values, so a peer may legitimately
        // send up to the 62-bit varint maximum; `Int(clamping:)` saturates the (absurd) over-`Int.max`
        // case instead of rejecting a spec-valid value. Safe in v1 because none of them sizes an
        // allocation: the QPACK dynamic table is pinned off (we advertise capacity / blocked-streams 0),
        // and `maxFieldSectionSize` only advises our own response-header size. FUTURE (v2 dynamic
        // table): bound any table allocation by OUR advertised capacity, never the peer's value.
        switch HTTP3SettingsParameter(rawValue: identifier) {
            case .qpackMaxTableCapacity:
                qpackMaxTableCapacity = Int(clamping: value)
            case .maxFieldSectionSize:
                maxFieldSectionSize = Int(clamping: value)
            case .qpackBlockedStreams:
                qpackBlockedStreams = Int(clamping: value)
            case .enableConnectProtocol:
                guard value <= 1 else {
                    throw .connection(.h3SettingsError, "ENABLE_CONNECT_PROTOCOL must be 0 or 1")
                }
                enableConnectProtocol = value == 1
            case nil:
                break  // unknown identifier — ignore (§7.2.4.1)
        }
    }

    /// Serializes these settings into a SETTINGS frame payload (RFC 9114 §7.2.4).
    public func encodePayload() -> [UInt8] {
        var output: [UInt8] = []
        append(.qpackMaxTableCapacity, UInt64(qpackMaxTableCapacity), to: &output)
        append(.qpackBlockedStreams, UInt64(qpackBlockedStreams), to: &output)
        if let maxFieldSectionSize {
            append(.maxFieldSectionSize, UInt64(maxFieldSectionSize), to: &output)
        }
        if enableConnectProtocol {
            append(.enableConnectProtocol, 1, to: &output)
        }
        return output
    }

    private func append(
        _ parameter: HTTP3SettingsParameter, _ value: UInt64, to output: inout [UInt8]
    ) {
        QUICVarint.encode(parameter.rawValue, into: &output)
        QUICVarint.encode(value, into: &output)
    }
}
