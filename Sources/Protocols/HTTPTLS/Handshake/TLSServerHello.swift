//
//  TLSServerHello.swift
//  HTTPTLS
//
//  RFC 8446 §4.1.3/§4.1.4 — the ServerHello and HelloRetryRequest encoders. Both share the
//  ServerHello wire shape; HRR is distinguished solely by the special SHA-256("HelloRetryRequest")
//  random value (§4.1.3). Extension order is fixed to the RFC 8448 traces' order —
//  pre_shared_key, key_share, cookie, supported_versions — so the byte-exact replay gates hold
//  (any §4.2-legal order would be conformant; one order is testable).
//

/// The ServerHello / HelloRetryRequest encoder (RFC 8446 §4.1.3/§4.1.4).
enum TLSServerHelloEncoder {
    /// §4.1.3's special HRR random: SHA-256 of "HelloRetryRequest".
    static let helloRetryRequestRandom: [UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
        0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
        0xC8, 0xA8, 0x33, 0x9C
    ]

    /// The frozen `legacy_version` 0x0303 every 1.3 ServerHello carries (§4.1.3).
    private static let legacyVersion: UInt16 = 0x0303
    /// The §4.2.1 selected version: TLS 1.3.
    private static let tls13: UInt16 = 0x0304

    /// Encodes a ServerHello (§4.1.3) for the negotiated parameters.
    ///
    /// - Parameters:
    ///   - random: The 32-octet server random (entropy-seam supplied).
    ///   - sessionIDEcho: The client's `legacy_session_id`, echoed verbatim (§4.1.3).
    ///   - suite: The selected cipher suite.
    ///   - selectedIdentity: The §4.2.11 `selected_identity`, when resuming via PSK.
    ///   - keyShareGroup: The selected group (§4.2.8).
    ///   - keyExchange: The server's public share for that group.
    /// - Returns: The framed ServerHello message octets.
    static func serverHello(
        random: [UInt8],
        sessionIDEcho: [UInt8],
        suite: TLSCipherSuite,
        selectedIdentity: UInt16?,
        keyShareGroup: TLSNamedGroup,
        keyExchange: [UInt8]
    ) -> [UInt8] {
        TLSHandshakeBuilder.message(.serverHello) { message in
            fixedFields(&message, random: random, sessionIDEcho: sessionIDEcho, suite: suite)
            message.vector16 { extensions in
                if let selectedIdentity {
                    // §4.2.11: the server's answer is just the selected identity index.
                    extensions.extensionField(.preSharedKey) { $0.u16(selectedIdentity) }
                }
                extensions.extensionField(.keyShare) { body in
                    body.u16(keyShareGroup.rawValue)  // §4.2.8 server share
                    body.vector16 { $0.raw(keyExchange) }
                }
                extensions.extensionField(.supportedVersions) { $0.u16(tls13) }  // §4.2.1
            }
        }
    }

    /// Encodes a HelloRetryRequest (§4.1.4): the ServerHello shape under the special random,
    /// with `key_share` naming only the requested group and an optional stateless `cookie`.
    static func helloRetryRequest(
        sessionIDEcho: [UInt8],
        suite: TLSCipherSuite,
        selectedGroup: TLSNamedGroup,
        cookie: [UInt8]?
    ) -> [UInt8] {
        TLSHandshakeBuilder.message(.serverHello) { message in
            fixedFields(
                &message,
                random: helloRetryRequestRandom,
                sessionIDEcho: sessionIDEcho,
                suite: suite
            )
            message.vector16 { extensions in
                extensions.extensionField(.keyShare) { $0.u16(selectedGroup.rawValue) }  // §4.2.8
                if let cookie {
                    extensions.extensionField(.cookie) { body in
                        body.vector16 { $0.raw(cookie) }  // §4.2.2
                    }
                }
                extensions.extensionField(.supportedVersions) { $0.u16(tls13) }  // §4.2.1
            }
        }
    }

    /// The shared §4.1.3 fixed fields: version, random, echo, suite, null compression.
    private static func fixedFields(
        _ message: inout TLSHandshakeBuilder,
        random: [UInt8],
        sessionIDEcho: [UInt8],
        suite: TLSCipherSuite
    ) {
        message.u16(legacyVersion)
        message.raw(random)
        message.vector8 { $0.raw(sessionIDEcho) }
        message.u16(suite.rawValue)
        message.u8(0)  // §4.1.3 legacy_compression_method = 0
    }
}
