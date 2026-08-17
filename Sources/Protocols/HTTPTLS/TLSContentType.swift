//
//  TLSContentType.swift
//  HTTPTLS
//
//  RFC 8446 §5.1 — the `ContentType` of a TLS record. TLS 1.3 keeps four live values (plus the
//  reserved `invalid(0)`, which is never valid on the wire and therefore not modeled as a case):
//  an unknown octet is a caller-visible parse failure, not a trap. The same values double as the
//  §5.2 *inner* content type carried at the tail of a `TLSInnerPlaintext`.
//

/// A TLS record content type (RFC 8446 §5.1) — also the §5.2 inner content type.
public enum TLSContentType: UInt8, Sendable, Equatable {
    /// A `change_cipher_spec` compatibility record (RFC 8446 §5, Appendix D.4).
    case changeCipherSpec = 20
    /// An alert record (RFC 8446 §6).
    case alert = 21
    /// A handshake record (RFC 8446 §4).
    case handshake = 22
    /// An application-data record — also the outer type of every protected record (RFC 8446 §5.2).
    case applicationData = 23
}
