//
//  TLSTicketKey.swift
//  HTTPTLS
//
//  One ticket-encryption key for the stateless vault: an 8-octet public key NAME (written in
//  the clear at the head of every ticket so the redeeming host can pick the right key without
//  trial decryption) and a 256-bit AES-GCM secret. Rotation-ready by construction: a vault
//  holds several of these, seals under the first, opens under whichever name matches — the
//  caller rotates by prepending a fresh key and eventually dropping the old (the standard
//  STEK rotation shape; cf. RFC 5077 §5.5's stateless-ticket guidance carried into RFC 8446
//  §4.6.1's opaque ticket).
//

public import Crypto

/// A named ticket-encryption key (8-octet name + AES-256-GCM secret).
public struct TLSTicketKey: Sendable {
    /// The name length written at the head of every ticket.
    public static let nameLength = 8

    /// The public key name (never secret — it only selects the key).
    public let name: [UInt8]
    /// The AES-256-GCM ticket-sealing secret.
    public let secret: SymmetricKey

    /// Creates a ticket key; nil unless the name is exactly 8 octets and the secret 256 bits.
    public init?(name: [UInt8], secret: SymmetricKey) {
        guard name.count == Self.nameLength, secret.bitCount == 256 else {
            return nil
        }
        self.name = name
        self.secret = secret
    }
}
