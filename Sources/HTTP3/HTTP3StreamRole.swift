//
//  HTTP3StreamRole.swift
//  HTTP3
//
//  RFC 9114 §6 — the role a QUIC stream plays in an HTTP/3 connection. Request and response exchange
//  happens on client-initiated bidirectional streams (§6.1). Each endpoint also opens unidirectional
//  streams (§6.2) whose first byte is a variable-length Stream Type: the control stream (0x00), push
//  streams (0x01), and the QPACK encoder (0x02) and decoder (0x03) streams. Unknown unidirectional
//  stream types (including the reserved grease types) are tolerated and their data discarded (§6.2 /
//  §8.1: the stream is aborted with H3_STREAM_CREATION_ERROR only when a known type appears twice).
//

/// The role of a stream within an HTTP/3 connection (RFC 9114 §6).
public enum HTTP3StreamRole: Sendable, Equatable, Hashable {
    /// A client-initiated bidirectional request stream (RFC 9114 §6.1) — carries HEADERS/DATA.
    case request
    /// The control stream (unidirectional Stream Type 0x00, RFC 9114 §6.2.1) — SETTINGS, GOAWAY, …
    case control
    /// A push stream (unidirectional Stream Type 0x01, RFC 9114 §6.2.2).
    case push
    /// The QPACK encoder stream (unidirectional Stream Type 0x02, RFC 9204 §4.2).
    case qpackEncoder
    /// The QPACK decoder stream (unidirectional Stream Type 0x03, RFC 9204 §4.2).
    case qpackDecoder
    /// An unrecognized unidirectional stream type (a reserved/grease type, RFC 9114 §6.2 / §7.2.8).
    case reserved(UInt64)

    /// The §6.2 unidirectional Stream Type byte for this role, or `nil` for a bidirectional request
    /// stream (which carries no Stream Type prefix).
    public var streamType: UInt64? {
        switch self {
            case .request: nil
            case .control: 0x00
            case .push: 0x01
            case .qpackEncoder: 0x02
            case .qpackDecoder: 0x03
            case .reserved(let type): type
        }
    }

    /// Classifies a unidirectional stream from its §6.2 Stream Type, mapping unknown types to
    /// ``reserved(_:)``.
    public init(streamType: UInt64) {
        switch streamType {
            case 0x00: self = .control
            case 0x01: self = .push
            case 0x02: self = .qpackEncoder
            case 0x03: self = .qpackDecoder
            default: self = .reserved(streamType)
        }
    }

    /// Whether this is a critical stream whose closure is a fatal error (RFC 9114 §6.2.1 — the control
    /// and QPACK streams; their closure is H3_CLOSED_CRITICAL_STREAM).
    public var isCritical: Bool {
        switch self {
            case .control, .qpackEncoder, .qpackDecoder: true
            case .request, .push, .reserved: false
        }
    }
}
