//
//  RFC8448ResumedServer.swift
//  HTTPTLSTests
//
//  RFC 8448 §4 — the Resumed 0-RTT trace's SERVER-side values Phase 3b needs on top of
//  ``RFC8448Resumed``: the published server ephemeral (the injection seam's input) and the
//  server's ServerHello (the byte-exact comparison target — the rest of the §4 server flight
//  is NOT comparable, because the trace's server ACCEPTS early data and this server rejects
//  it, §4.2.10's first option).
//  Byte-exact values MACHINE-EXTRACTED from the RFC 8448 text (rfc-editor.org/rfc/rfc8448.txt):
//  every labeled “name (N octets): hex” block of the trace was parsed with its octet count
//  asserted against the hex, so no vector octet was ever hand-typed. Regeneration is a rerun
//  of the same extraction; the RFC text is the single source of truth.
//

/// The RFC 8448 §4 trace's server-side values (byte-exact, machine-extracted).
enum RFC8448ResumedServer {
    /// RFC 8448: {server} create an ephemeral x25519 key pair — “private key” (32 octets).
    static let serverEphemeralPrivateKey = RFC8448Hex.bytes(
        """
        de5b4476e7b490b2652d338acbf2948066f255f9440e23b98fc69835298dc107
        """
    )

    /// RFC 8448: {server} construct a ServerHello handshake message — “ServerHello” (96 octets).
    static let serverHello = RFC8448Hex.bytes(
        """
        0200005c03033ccfd2dec890222763472ae8136777c9d7358777bb66e91ea512
        2495f559ea2d00130100003400290002000000330024001d0020121761ee42c3
        33e1b9e77b60dd57c2053cd94512ab47f115e86eff50942cea31002b00020304
        """
    )
}
