//
//  HTTP3SettingsParameter.swift
//  HTTP3
//
//  RFC 9114 §7.2.4 — the HTTP/3 SETTINGS frame conveys configuration as a sequence of (Identifier,
//  Value) pairs, each a variable-length integer. This models the known parameters (§7.2.4.2 / RFC 9204
//  §5 / RFC 9220), parses a received payload, and serializes one to send. Per §7.2.4.1, identifiers
//  reserved from HTTP/2 (0x02/0x03/0x04/0x05) and any duplicate identifier are a connection error of
//  type H3_SETTINGS_ERROR; unknown identifiers are ignored. A structurally malformed payload (a
//  truncated pair) is H3_FRAME_ERROR.
//

/// A defined HTTP/3 SETTINGS parameter identifier (RFC 9114 §7.2.4.2 / RFC 9204 §5 / RFC 9220).
public enum HTTP3SettingsParameter: UInt64, Sendable, Equatable {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x01) — the QPACK dynamic table bound (RFC 9204 §5).
    case qpackMaxTableCapacity = 0x01
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE` (0x06) — the advisory maximum decoded header-list size.
    case maxFieldSectionSize = 0x06
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` (0x07) — the QPACK blocked-streams bound (RFC 9204 §5).
    case qpackBlockedStreams = 0x07
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) — permits Extended CONNECT (RFC 9220 / RFC 8441).
    case enableConnectProtocol = 0x08
}
