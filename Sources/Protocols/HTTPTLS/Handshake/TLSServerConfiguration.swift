//
//  TLSServerConfiguration.swift
//  HTTPTLS
//
//  The per-listener contract a ``TLSServerConnection`` negotiates under. Preference lists are
//  SERVER-preference (first match wins, RFC 8446 §4.1.1); ALPN carries NO default — the
//  protocol list is the caller's per-listener contract (the QUIC ALPN lesson: baking a default
//  into the engine silently mis-negotiates every listener that forgets to set it). Everything
//  nondeterministic or deployment-specific rides a seam: entropy, identity signing, ticket
//  sealing, client-certificate verification, the wall clock, and the HRR cookie.
//

internal import struct Foundation.Date

/// The negotiation contract for one TLS 1.3 server listener (RFC 8446 §4).
public struct TLSServerConfiguration: Sendable {
    /// Cipher suites in server-preference order (§4.1.1; default: all three §B.4 suites,
    /// AES-128-GCM first per §9.1's mandatory-to-implement).
    public var cipherSuites: [TLSCipherSuite] = [
        .aes128GcmSha256, .aes256GcmSha384, .chaCha20Poly1305Sha256
    ]
    /// Key-exchange groups in server-preference order (§4.2.7; implemented groups only —
    /// unimplemented entries are ignored during negotiation).
    public var groups: [TLSNamedGroup] = [.x25519, .secp256r1]
    /// Signature schemes acceptable for CertificateVerify, both directions (§4.2.3).
    ///
    /// Server-preference order. The default lists what the seams can produce/verify plus the
    /// RSA-PSS family for identity providers that sign RSA (§9.1's mandatory rows).
    public var signatureSchemes: [TLSSignatureScheme] = [
        .ecdsaSecp256r1Sha256, .ecdsaSecp384r1Sha384, .ed25519, .rsaPssRsaeSha256,
        .rsaPssRsaeSha384, .rsaPssRsaeSha512
    ]
    /// The ALPN contract (RFC 7301), server-preference order.
    ///
    /// EMPTY by default — deliberately: the listener owns its protocol list. Empty = ALPN not
    /// negotiated; non-empty + client offer + empty intersection = `no_application_protocol`.
    public var alpnProtocols: [String] = []
    /// The client-authentication policy (§4.3.2/§4.4.2.4; default `.none`).
    public var clientAuthentication: TLSClientAuthenticationMode = .none
    /// Verifies client CertificateVerify signatures (§4.4.3).
    ///
    /// The default covers ECDSA P-256/384/521 + Ed25519; inject an `_CryptoExtras`-backed
    /// verifier for RSA clients.
    public var certificateVerifier: any TLSCertificateSignatureVerifier =
        TLSECDSACertificateVerifier()
    /// The ticket vault (§4.6.1).
    ///
    /// Nil = no tickets issued, no resumption accepted.
    public var ticketVault: (any TLSTicketVault)?
    /// `ticket_lifetime` for issued tickets (§4.6.1 caps at 604800; default one day).
    public var ticketLifetimeSeconds: UInt32 = 86_400
    /// Appendix D.4 middlebox-compatibility mode: the unprotected `change_cipher_spec`
    /// right after the first ServerHello/HelloRetryRequest.
    ///
    /// Off by default (the RFC 8448 §3 trace shape); CCS TOLERANCE on receive is
    /// unconditional (§5).
    public var middleboxCompatibilityMode = false
    /// The §4.2.7 EncryptedExtensions `supported_groups` hint (empty = not sent).
    public var supportedGroupsHint: [TLSNamedGroup] = []
    /// Our RFC 8449 `record_size_limit` answer, echoed only when the client offers it too.
    ///
    /// Nil = never negotiate the extension. The peer's own limit is honored when negotiated.
    public var recordSizeLimit: Int? = TLSRecordLimits.maxPlaintextLength + 1
    /// Stateless HRR cookie factory (§4.2.2): given Hash(ClientHello1), the cookie to embed.
    ///
    /// Nil = HRR without a cookie (this machine keeps connection state regardless).
    public var cookieProvider: (@Sendable (_ clientHello1Hash: [UInt8]) -> [UInt8])?
    /// The §4.2.10 skip budget for rejected early data: how many ciphertext octets may fail
    /// deprotection before the connection aborts (the "configured max_early_data_size").
    public var maxEarlyDataSkipOctets = 65_536
    /// The handshake-message reassembly cap (flood protection; certificate chains bound it).
    public var maxHandshakeMessageLength = 131_072
    /// The wall clock (seconds) for ticket lifetimes — injectable for tests.
    public var now: @Sendable () -> UInt64 = {
        UInt64(Date().timeIntervalSince1970.rounded(.down))
    }
    /// The randomness/ephemeral-key seam (§4.1.3/§4.2.8) — the RFC 8448 injection point.
    public var entropy: any TLSServerEntropy = TLSSystemEntropy()

    /// Creates the default configuration (no ALPN, no client auth, no tickets).
    public init() {
        // Every field carries a safe default; listeners override what their contract needs.
    }
}
