//
//  HTTPProtocolVersion.swift
//  HTTPCore
//
//  The HTTP version an error or message belongs to (Phase 3.4) — the discriminator a consumer reads off a
//  unified ``HTTPProtocolError`` to tell which protocol's parser or engine raised it. The raw value is the
//  wire name (`HTTP/1.1`, `HTTP/2`, `HTTP/3`).
//

/// An HTTP protocol version (RFC 9112 / RFC 9113 / RFC 9114).
public enum HTTPProtocolVersion: String, Sendable, Equatable, CaseIterable {
    case http1 = "HTTP/1.1"
    case http2 = "HTTP/2"
    case http3 = "HTTP/3"
}
