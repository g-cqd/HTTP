//
//  HTTP2Settings.swift
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
}

/// The set of known HTTP/2 SETTINGS parameters, with protocol defaults (RFC 9113 §6.5.2).
public struct HTTP2Settings: Sendable, Equatable {

    /// Each parameter is 2 octets of identifier and 4 octets of value (RFC 9113 §6.5.1).
    public static let parameterLength = 6

    /// HPACK dynamic table size in octets (default 4096).
    public var headerTableSize = 4096
    /// Whether server push is enabled (default true).
    public var enablePush = true
    /// Maximum concurrent streams, or `nil` for unlimited (the default).
    public var maxConcurrentStreams: Int?
    /// Initial flow-control window in octets (default 65,535).
    public var initialWindowSize = 65_535
    /// Maximum frame payload size in octets (default 16,384).
    public var maxFrameSize = 16_384
    /// Advisory maximum header list size in octets, or `nil` for unset (the default).
    public var maxHeaderListSize: Int?

    /// Creates a settings set at the protocol defaults.
    public init() {}

    /// Applies a received SETTINGS payload, updating the known parameters (RFC 9113 §6.5).
    ///
    /// The payload length must be a multiple of 6 (else FRAME_SIZE_ERROR); each parameter is
    /// validated per §6.5.2; unknown identifiers are ignored.
    public mutating func apply(_ payload: RawSpan) throws(HTTP2Error) {
        guard payload.byteCount.isMultiple(of: Self.parameterLength) else {
            throw .connection(.frameSizeError, "SETTINGS length must be a multiple of 6")
        }
        var offset = 0
        while offset < payload.byteCount {
            let identifier =
                UInt16(payload.unsafeLoad(fromByteOffset: offset, as: UInt8.self)) << 8
                | UInt16(payload.unsafeLoad(fromByteOffset: offset + 1, as: UInt8.self))
            let value =
                UInt32(payload.unsafeLoad(fromByteOffset: offset + 2, as: UInt8.self)) << 24
                | UInt32(payload.unsafeLoad(fromByteOffset: offset + 3, as: UInt8.self)) << 16
                | UInt32(payload.unsafeLoad(fromByteOffset: offset + 4, as: UInt8.self)) << 8
                | UInt32(payload.unsafeLoad(fromByteOffset: offset + 5, as: UInt8.self))
            try applyParameter(identifier: identifier, value: value)
            offset += Self.parameterLength
        }
    }

    /// Validates and stores one parameter; unknown identifiers are ignored (RFC 9113 §6.5.2).
    private mutating func applyParameter(identifier: UInt16, value: UInt32) throws(HTTP2Error) {
        switch HTTP2SettingsParameter(rawValue: identifier) {
        case .headerTableSize:
            headerTableSize = Int(value)
        case .enablePush:
            guard value <= 1 else {
                throw .connection(.protocolError, "ENABLE_PUSH must be 0 or 1")
            }
            enablePush = value == 1
        case .maxConcurrentStreams:
            maxConcurrentStreams = Int(value)
        case .initialWindowSize:
            guard value <= 0x7FFF_FFFF else {
                throw .connection(.flowControlError, "INITIAL_WINDOW_SIZE exceeds 2^31-1")
            }
            initialWindowSize = Int(value)
        case .maxFrameSize:
            guard value >= 16_384, value <= 0xFF_FFFF else {
                throw .connection(.protocolError, "MAX_FRAME_SIZE outside 2^14...2^24-1")
            }
            maxFrameSize = Int(value)
        case .maxHeaderListSize:
            maxHeaderListSize = Int(value)
        case nil:
            break  // unknown identifier — ignore (§6.5.2)
        }
    }

    /// Serializes these settings into a SETTINGS frame payload (RFC 9113 §6.5.1).
    public func encodePayload() -> [UInt8] {
        var output = [UInt8]()
        append(.headerTableSize, UInt32(headerTableSize), to: &output)
        append(.enablePush, enablePush ? 1 : 0, to: &output)
        if let maxConcurrentStreams {
            append(.maxConcurrentStreams, UInt32(maxConcurrentStreams), to: &output)
        }
        append(.initialWindowSize, UInt32(initialWindowSize), to: &output)
        append(.maxFrameSize, UInt32(maxFrameSize), to: &output)
        if let maxHeaderListSize {
            append(.maxHeaderListSize, UInt32(maxHeaderListSize), to: &output)
        }
        return output
    }

    private func append(
        _ parameter: HTTP2SettingsParameter,
        _ value: UInt32,
        to output: inout [UInt8]
    ) {
        output.append(UInt8(parameter.rawValue >> 8))
        output.append(UInt8(parameter.rawValue & 0xFF))
        output.append(UInt8((value >> 24) & 0xFF))
        output.append(UInt8((value >> 16) & 0xFF))
        output.append(UInt8((value >> 8) & 0xFF))
        output.append(UInt8(value & 0xFF))
    }
}
