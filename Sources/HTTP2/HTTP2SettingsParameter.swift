//
//  HTTP2SettingsParameter.swift
//  HTTP2
//
//  RFC 9113 §6.5 — the SETTINGS frame conveys configuration as a list of 6-octet parameters (a 16-bit
//  identifier and a 32-bit value). This models the set of known parameters (§6.5.2) with their
//  protocol defaults, parsing a received payload (validating per-parameter and overall length) and
//  serializing one to send. Unknown identifiers are ignored (§6.5.2).
//

/// A defined SETTINGS parameter identifier (RFC 9113 §6.5.2).
public enum HTTP2SettingsParameter: UInt16, Sendable, Equatable {
    /// `SETTINGS_HEADER_TABLE_SIZE` (0x01) — HPACK dynamic table bound.
    case headerTableSize = 0x01
    /// `SETTINGS_ENABLE_PUSH` (0x02) — whether server push is permitted.
    case enablePush = 0x02
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (0x03).
    case maxConcurrentStreams = 0x03
    /// `SETTINGS_INITIAL_WINDOW_SIZE` (0x04) — initial flow-control window.
    case initialWindowSize = 0x04
    /// `SETTINGS_MAX_FRAME_SIZE` (0x05).
    case maxFrameSize = 0x05
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (0x06).
    case maxHeaderListSize = 0x06
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) — permits the Extended CONNECT method (RFC 8441 §3).
    case enableConnectProtocol = 0x08
}
