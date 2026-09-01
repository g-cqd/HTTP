//
//  TLSSystemEntropy.swift
//  HTTPTLS
//
//  The production ``TLSServerEntropy``: ephemeral keys come straight from swift-crypto's key
//  generators (never hand-rolled scalars), and the server random / ticket obfuscator from the
//  standard library's `SystemRandomNumberGenerator` — the platform CSPRNG (`arc4random_buf` /
//  `getrandom`), which is the stdlib's documented cryptographically-secure default.
//

internal import Crypto

/// The default entropy source: platform CSPRNG + swift-crypto key generation.
public struct TLSSystemEntropy: TLSServerEntropy {
    /// Creates the system entropy source.
    public init() {
        // Stateless — generators are drawn fresh per call.
    }

    /// 32 CSPRNG octets for the ServerHello random (§4.1.3).
    public func serverRandom() -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        for _ in 0 ..< 4 {
            var word = generator.next() as UInt64
            for _ in 0 ..< 8 {
                bytes.append(UInt8(truncatingIfNeeded: word))
                word >>= 8
            }
        }
        return bytes
    }

    /// A fresh swift-crypto private key for the group, as raw octets.
    public func ephemeralPrivateKey(for group: TLSNamedGroup) -> [UInt8] {
        switch group {
            case .secp256r1:
                [UInt8](P256.KeyAgreement.PrivateKey().rawRepresentation)
            default:
                [UInt8](Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
        }
    }

    /// A CSPRNG §4.6.1 `ticket_age_add` (full 32-bit range, unbiased).
    public func ticketAgeAdd() -> UInt32 {
        var generator = SystemRandomNumberGenerator()
        return UInt32(truncatingIfNeeded: generator.next() as UInt64)
    }
}
