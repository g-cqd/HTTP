//
//  TLSKeyExchange.swift
//  HTTPTLS
//
//  RFC 8446 §4.2.8.2/§7.4 — the (EC)DHE leg over swift-crypto: X25519
//  (`Curve25519.KeyAgreement`, RFC 7748) and secp256r1 (`P256.KeyAgreement`, uncompressed
//  X9.62 points). Peer-share validation is swift-crypto's — on-curve checks, point decoding,
//  and RFC 7748's all-zero-output rejection all live in the library, and every failure maps to
//  §4.2.8.2's `illegal_parameter` ("Peers MUST validate each other's public key Y").
//

internal import Crypto

/// The §7.4 key-exchange leg for the implemented groups (swift-crypto only).
enum TLSKeyExchange {
    /// Derives the public share octets for `group` from a raw private key.
    ///
    /// X25519 shares are the 32 raw octets (RFC 7748); P-256 shares are the 65-octet
    /// uncompressed X9.62 point (§4.2.8.2 "the binary format of ANSI X9.62").
    static func publicShare(
        group: TLSNamedGroup, privateKey: [UInt8]
    ) throws(TLSHandshakeError) -> [UInt8] {
        switch group {
            case .x25519:
                guard
                    let key = try? Curve25519.KeyAgreement.PrivateKey(
                        rawRepresentation: privateKey
                    )
                else {
                    throw .internalError("x25519 private key")
                }
                return [UInt8](key.publicKey.rawRepresentation)
            case .secp256r1:
                guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
                else {
                    throw .internalError("secp256r1 private key")
                }
                return [UInt8](key.publicKey.x963Representation)
            default:
                throw .internalError("unimplemented group \(group.rawValue)")
        }
    }

    /// Runs the key agreement between our raw private key and the peer's share (§7.4).
    ///
    /// Every share defect — wrong length, off-curve point, low-order X25519 input — is the
    /// single §4.2.8.2 outcome `illegal_parameter`.
    static func sharedSecret(
        group: TLSNamedGroup, privateKey: [UInt8], peerShare: [UInt8]
    ) throws(TLSHandshakeError) -> SharedSecret {
        guard peerShare.count == group.keyExchangeLength else {
            throw .illegalParameter("key_exchange length for group \(group.rawValue)")
        }
        switch group {
            case .x25519:
                guard
                    let key = try? Curve25519.KeyAgreement.PrivateKey(
                        rawRepresentation: privateKey
                    ),
                    let peer = try? Curve25519.KeyAgreement.PublicKey(
                        rawRepresentation: peerShare
                    ),
                    let secret = try? key.sharedSecretFromKeyAgreement(with: peer)
                else {
                    throw .illegalParameter("x25519 key agreement")  // §4.2.8.2
                }
                return secret
            case .secp256r1:
                guard
                    let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey),
                    let peer = try? P256.KeyAgreement.PublicKey(x963Representation: peerShare),
                    let secret = try? key.sharedSecretFromKeyAgreement(with: peer)
                else {
                    throw .illegalParameter("secp256r1 key agreement")  // §4.2.8.2
                }
                return secret
            default:
                throw .internalError("unimplemented group \(group.rawValue)")
        }
    }
}
