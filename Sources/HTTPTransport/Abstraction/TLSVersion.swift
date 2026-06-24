//
//  TLSVersion.swift
//  HTTPTransport
//
//  The switchable backbone flag, its configuration, and transport errors.
//

/// A TLS protocol version, expressed backbone-agnostically (each backbone maps it to its platform
/// TLS API).
///
/// TLS 1.3 is the strict default; 1.2 is the BCP 195 baseline for broader compatibility.
public enum TLSVersion: Sendable, Equatable {
    /// TLS 1.2 (RFC 5246) — the BCP 195 minimum baseline.
    case tlsV12
    /// TLS 1.3 (RFC 8446) — AEAD-only with forward secrecy; the strict default.
    case tlsV13
}
