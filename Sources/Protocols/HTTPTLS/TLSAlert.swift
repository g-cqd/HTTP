//
//  TLSAlert.swift
//  HTTPTLS
//
//  RFC 8446 §6 — an Alert message: a two-octet `AlertLevel` + `AlertDescription` pair. In TLS 1.3
//  the severity is implicit in the description and "the 'level' field ... can safely be ignored"
//  (§6), so the level octet is carried verbatim rather than validated; §6 also requires alert
//  messages to fill exactly one record (never fragmented, never coalesced), which is what the
//  record layer enforces when it parses one.
//

/// A TLS alert (RFC 8446 §6): the raw level octet plus the typed description.
public struct TLSAlert: Sendable, Equatable {
    /// The legacy `AlertLevel` octet — carried, not interpreted (RFC 8446 §6: safely ignored).
    public let level: UInt8
    /// The alert description (RFC 8446 §6.2's registry; unknown values are treated as errors).
    public let description: TLSAlertDescription

    /// The §6 `AlertLevel.warning(1)` octet, used when serializing `close_notify`/`user_canceled`.
    public static let warningLevel: UInt8 = 1
    /// The §6 `AlertLevel.fatal(2)` octet, used when serializing error alerts.
    public static let fatalLevel: UInt8 = 2

    /// Creates an alert from its two wire octets.
    public init(level: UInt8, description: TLSAlertDescription) {
        self.level = level
        self.description = description
    }

    /// Whether this alert closes the connection: everything but `close_notify`/`user_canceled`
    /// is an error alert in TLS 1.3 (RFC 8446 §6.2, including unknown alert types).
    public var isError: Bool {
        description != .closeNotify && description != .userCanceled
    }
}
