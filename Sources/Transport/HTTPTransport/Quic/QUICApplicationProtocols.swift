//
//  QUICApplicationProtocols.swift
//  HTTPTransport
//
//  The ALPN identifiers (RFC 7301) a QUIC listener offers — the one place either QUIC backbone gets
//  them, and deliberately NOT ``TransportTLS/applicationProtocols``.
//
//  `TransportTLS` carries a single ALPN list that the TCP TLS listener and the QUIC listener were
//  both reading. That list's documented default is the TCP set `["h2", "http/1.1"]`: identifiers
//  registered for HTTP over TLS-over-TCP (RFC 9113 §3.3, RFC 9112) which cannot name a protocol over
//  QUIC. So unless a caller happened to spell `["h3"]` — which every in-repo test does and no real
//  deployment would, because the same list must also serve the TCP listener — the QUIC listener
//  advertised only identifiers no HTTP/3 client offers, and shared nothing with the peer.
//
//  RFC 9001 §8.1 makes that terminal rather than merely unnegotiated: "endpoints MUST immediately
//  close a connection … with a no_application_protocol TLS alert … if an application protocol is not
//  negotiated". Measured against Apple's stack the alert is `internal_error` (80, QUIC CRYPTO_ERROR
//  0x150) rather than the mandated `no_application_protocol` (120, 0x178) — a platform deviation, but
//  the connection dies either way, ~12 ms after the ClientHello.
//
//  Hence: the QUIC listener's ALPN is a property of the protocol it serves, not of the caller's TCP
//  TLS configuration. HTTP/3 has exactly one identifier and this is it.
//
//  Standards: ALPN (RFC 7301); the `h3` identifier (RFC 9114 §3.1, IANA "TLS Application-Layer
//  Protocol Negotiation (ALPN) Protocol IDs"); mandatory ALPN in QUIC-TLS (RFC 9001 §8.1).
//

/// The ALPN identifiers (RFC 7301) an HTTP/3-over-QUIC listener offers.
enum QUICApplicationProtocols {
    /// The IANA-registered ALPN identifier for HTTP/3 (RFC 9114 §3.1).
    static let http3 = "h3"

    /// The complete ALPN list a QUIC listener offers — exactly `["h3"]`.
    ///
    /// Not derived from ``TransportTLS/applicationProtocols``: that list configures the TCP TLS
    /// listener, and the draft `h3-NN` identifiers are excluded on purpose, since this engine
    /// implements RFC 9114 and advertising a draft revision it cannot speak would trade one
    /// mis-negotiation for a worse one.
    static let offered = [http3]
}
