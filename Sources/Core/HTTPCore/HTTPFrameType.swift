//
//  HTTPFrameType.swift
//  HTTPCore
//
//  The frame-type taxonomy shared by HTTP/2 (RFC 9113 §6) and HTTP/3 (RFC 9114 §7.2): both model a frame
//  type as a `RawRepresentable` integer wrapper (so unknown types stay representable and ignorable) and
//  both define the same five core types. This protocol (Phase 3.5) names that common shape so generic
//  code — tooling, logging, tests — can refer to "an HTTP frame type" across versions.
//
//  Deliberately limited to the *taxonomy*: the wire layout is NOT unified. An HTTP/2 frame carries an
//  8-bit type in a fixed 9-octet binary header with flags and a stream id (RFC 9113 §4.1); an HTTP/3
//  frame carries a varint type and length on a QUIC stream that already provides the stream identity
//  (RFC 9114 §7.1). They share no header. Each protocol keeps its own version-specific types (HTTP/2's
//  `priority`/`rstStream`/`windowUpdate`/`continuation`; HTTP/3's `cancelPush`/`maxPushID`).
//

/// A frame type common to HTTP/2 and HTTP/3 — a `RawRepresentable` integer naming the five core frames.
public protocol HTTPFrameType: Sendable, Equatable, Hashable, RawRepresentable
where RawValue: FixedWidthInteger & Sendable {
    /// The `DATA` frame type (RFC 9113 §6.1 / RFC 9114 §7.2.1).
    static var data: Self { get }

    /// The `HEADERS` frame type (RFC 9113 §6.2 / RFC 9114 §7.2.2).
    static var headers: Self { get }

    /// The `SETTINGS` frame type (RFC 9113 §6.5 / RFC 9114 §7.2.4).
    static var settings: Self { get }

    /// The `PUSH_PROMISE` frame type (RFC 9113 §6.6 / RFC 9114 §7.2.5).
    static var pushPromise: Self { get }

    /// The `GOAWAY` frame type (RFC 9113 §6.8 / RFC 9114 §7.2.6).
    static var goAway: Self { get }
}
