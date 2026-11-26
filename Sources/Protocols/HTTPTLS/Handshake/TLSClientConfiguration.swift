//
//  TLSClientConfiguration.swift
//  HTTPTLS
//
//  The per-connection contract a ``TLSClientConnection`` negotiates under (RFC 8446 §4): SNI
//  host name (RFC 6066 §3), ALPN protocol offer (RFC 7301), cipher suites, groups, signature
//  schemes, signature verifier (`TLSECDSACertificateVerifier` by default; inject
//  `TLSRSACertificateVerifier` from `HTTPTLSRSA` to verify RSA-PSS server certificates), and
//  pinned X.509 trust roots (`TLSX509ChainValidator` + RFC 6125 `ServerIdentityPolicy`).
//

/// The negotiation contract for one TLS 1.3 client connection (RFC 8446 §4).
public struct TLSClientConfiguration: Sendable {
    /// The SNI host name offered in `server_name` (RFC 6066 §3) and checked against the leaf SAN
    /// via `ServerIdentityPolicy` (RFC 6125); `nil` omits SNI and checks the CA path only.
    public var serverName: String?
    /// DER-encoded root CA certificates pinned as trust anchors (RFC 5280 §6).
    public var trustRootsDER: [[UInt8]]
    /// Cipher suites offered in client-preference order (§4.1.2).
    public var cipherSuites: [TLSCipherSuite] = TLSDefaults.cipherSuites
    /// Key-exchange groups offered in `supported_groups` (§4.2.7); the first group's key share
    /// is sent optimistically in `ClientHello1`.
    public var groups: [TLSNamedGroup] = TLSDefaults.groups
    /// Signature schemes offered in `signature_algorithms` (§4.2.3).
    public var signatureSchemes: [TLSSignatureScheme] = [
        .ecdsaSecp256r1Sha256, .ecdsaSecp384r1Sha384, .ecdsaSecp521r1Sha512, .ed25519,
        .rsaPssRsaeSha256, .rsaPssRsaeSha384, .rsaPssRsaeSha512
    ]
    /// ALPN protocols offered in client-preference order (RFC 7301); empty omits ALPN.
    public var alpnProtocols: [String] = []
    /// Verifies the server's `CertificateVerify` signature (§4.4.3).
    public var certificateVerifier: any TLSCertificateSignatureVerifier =
        TLSECDSACertificateVerifier()
    /// Appendix D.4 middlebox-compatibility mode: send an unprotected `change_cipher_spec`
    /// after `ClientHello1` and wrap `legacy_session_id` in 32 random octets.
    public var middleboxCompatibilityMode = true
    /// Maximum reassembled handshake message length (bounds certificate chains).
    public var maxHandshakeMessageLength = 131_072
    /// Maximum consecutive peer `KeyUpdate` messages without intervening application data (§4.6.3).
    public var maxConsecutivePeerKeyUpdates = 32
    /// Randomness and ephemeral key source (§4.1.2 / §4.2.8).
    public var entropy: any TLSServerEntropy = TLSSystemEntropy()

    /// Creates a client configuration for `serverName` anchored to `trustRootsDER`.
    public init(serverName: String?, trustRootsDER: [[UInt8]]) {
        self.serverName = serverName
        self.trustRootsDER = trustRootsDER
    }
}
