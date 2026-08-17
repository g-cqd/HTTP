//
//  TLSKeyEpoch.swift
//  HTTPTLS
//
//  The per-direction key ladder the handshake drives through the record layer: unprotected
//  ClientHello/ServerHello records, then the §7.1 handshake traffic keys, then the application
//  traffic keys. TLS 1.3 puts no epoch on the wire — a record under retired keys simply fails
//  deprotection (§5.2) — so this ladder exists to order key INSTALLATION (strictly forward,
//  §7.1's stages) and to scope the §5/D.4 change_cipher_spec tolerance window.
//

/// One direction's key epoch: plaintext → handshake → application (RFC 8446 §7.1's stages).
public enum TLSKeyEpoch: Int, Sendable, Equatable, Comparable {
    /// No keys installed — ClientHello/ServerHello flow unprotected (§5.1).
    case plaintext = 0
    /// The §7.1 handshake traffic keys protect this direction.
    case handshake = 1
    /// The §7.1 application traffic keys (generation N under §7.2 ratchets) protect it.
    case application = 2

    /// Epochs are ordered by ladder position (installation may only climb).
    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// The next rung of the ladder, or nil at the top.
    public var next: Self? {
        Self(rawValue: rawValue + 1)
    }
}
