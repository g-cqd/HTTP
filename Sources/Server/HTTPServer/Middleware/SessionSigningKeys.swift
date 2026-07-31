//
//  SessionSigningKeys.swift
//  HTTPServer
//
//  The key set behind ``SessionMiddleware``'s signed cookie: a fail-closed length contract plus key
//  rotation. RFC 2104 §3 admits any key length, so an API that takes `[UInt8]` silently accepts an
//  empty or 4-octet "secret" — NIST SP 800-107r1 §5.3.4 requires HMAC key material at least as long as
//  the digest (32 octets for SHA-256), and this type refuses anything shorter (CWE-326, inadequate
//  encryption strength). Rotation exists because a signing key that can never be retired is a key that
//  never is: `current` signs, `previous` still verifies, so a deployment can roll a key without
//  invalidating every live session. The `SymmetricKey` values are built once, at init, never per
//  request.
//

internal import Crypto

/// The keys a session cookie is signed and verified with.
///
/// A key shorter than 32 octets is refused: HMAC-SHA256's security is bounded by its key length, and
/// NIST SP 800-107r1 §5.3.4 requires key material at least as long as the digest. Rotation: sign with
/// `current`, keep a retired key in `previous` until every cookie issued under it has expired, then
/// drop it.
public struct SessionSigningKeys: Sendable {
    /// The shortest accepted key, in octets — the SHA-256 digest length (NIST SP 800-107r1 §5.3.4).
    public static var minimumKeyLength: Int { Crypto.SHA256.Digest.byteCount }

    /// The key new cookies are signed with.
    private let current: SymmetricKey
    /// Retired keys that still verify, newest first.
    private let previous: [SymmetricKey]

    /// Creates the key set, or nil if any key is shorter than ``minimumKeyLength`` octets.
    ///
    /// `current` signs newly issued cookies and is tried first on verification. `previous` holds keys
    /// that have been rotated out but whose cookies are still live; drop a key from it once every
    /// cookie issued under it has expired.
    public init?(current: [UInt8], previous: [[UInt8]] = []) {
        let minimum = Self.minimumKeyLength
        guard current.count >= minimum, previous.allSatisfy({ $0.count >= minimum }) else {
            return nil
        }
        self.current = SymmetricKey(data: current)
        self.previous = previous.map { SymmetricKey(data: $0) }
    }

    /// Wraps key material already known to meet the length contract.
    private init(generated: SymmetricKey) {
        self.current = generated
        self.previous = []
    }

    /// A fresh 256-bit signing key from the system CSPRNG, with no retired keys.
    ///
    /// Suitable for a single-process deployment; a multi-process or restartable one must supply a
    /// stable key through ``init(current:previous:)``, or every restart invalidates every session.
    public static func random() -> Self {
        Self(generated: SymmetricKey(size: .bits256))
    }

    /// The RFC 2104 HMAC-SHA256 tag over `message` under the current key.
    func tag(for message: [UInt8]) -> [UInt8] {
        Array(HMAC<Crypto.SHA256>.authenticationCode(for: message, using: current))
    }

    /// Whether `tag` authenticates `message` under the current key or any retired one.
    ///
    /// Each comparison is constant-time (`HMAC.isValidAuthenticationCode`), so a near-miss tag cannot
    /// be refined byte by byte. The *number* of comparisons run reveals only which key matched — which
    /// key signed a given cookie is not secret, and a forged tag matches none of them, so a rejection
    /// always costs the full set.
    func isValid(tag: [UInt8], for message: [UInt8]) -> Bool {
        if authenticates(tag, message, current) {
            return true
        }
        for key in previous where authenticates(tag, message, key) {
            return true
        }
        return false
    }

    /// Whether `tag` is the RFC 2104 tag over `message` under `key`, compared in constant time.
    private func authenticates(_ tag: [UInt8], _ message: [UInt8], _ key: SymmetricKey) -> Bool {
        HMAC<Crypto.SHA256>
            .isValidAuthenticationCode(tag, authenticating: message, using: key)
    }
}
