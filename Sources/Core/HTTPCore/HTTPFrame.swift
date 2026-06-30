//
//  HTTPFrame.swift
//  HTTPCore
//
//  The shape a decoded HTTP/2 (RFC 9113 §6) or HTTP/3 (RFC 9114 §7.1) frame has in common: a payload of
//  octets. This protocol (Phase 3.5) names it so generic code can read any frame's body regardless of
//  version. The framing *around* the payload is not unified — an HTTP/2 frame pairs it with a binary
//  header (type, flags, stream id), an HTTP/3 frame with a varint type on its QUIC stream — so each
//  version keeps its own concrete `Frame` type and exposes its header alongside this requirement.
//

/// A decoded HTTP/2 or HTTP/3 frame, viewed only as its payload octets.
public protocol HTTPFrame: Sendable, Equatable {
    /// The frame payload octets (the bytes after the version-specific framing).
    var payload: [UInt8] { get }
}
