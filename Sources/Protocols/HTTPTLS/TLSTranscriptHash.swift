//
//  TLSTranscriptHash.swift
//  HTTPTLS
//
//  RFC 8446 §4.4.1 — the running `Transcript-Hash(M1, …, Mn)` over the handshake messages,
//  INCREMENTAL by construction: messages are folded into the hasher as they pass and are never
//  buffered here (the handshake machine of Phase 3b feeds it; the type lives with the key
//  schedule it parameterizes). The one special shape is HelloRetryRequest: after HRR the
//  transcript's leading ClientHello1 is REPLACED by a synthetic `message_hash` handshake message
//  (type 254) containing `Hash(ClientHello1)` — §4.4.1's construction, ``collapseForHelloRetry``.
//

public import Crypto

/// The incremental RFC 8446 §4.4.1 transcript hash (SHA-256 or SHA-384 per the suite).
public struct TLSTranscriptHash {
    /// The `HandshakeType.message_hash(254)` octet of §4.4.1's synthetic HRR message.
    static let messageHashType: UInt8 = 254

    /// The two suite hashes, held as live incremental hashers (one case per §7.1 hash).
    private enum Hasher {
        case sha256(SHA256)
        case sha384(SHA384)
    }

    /// The hash this transcript runs (fixed at negotiation).
    public let hash: TLSHashFunction
    /// The live hasher state.
    private var hasher: Hasher

    /// Creates an empty transcript for the suite's hash.
    public init(_ hash: TLSHashFunction) {
        self.hash = hash
        switch hash {
            case .sha256:
                hasher = .sha256(SHA256())
            case .sha384:
                hasher = .sha384(SHA384())
        }
    }

    /// Folds handshake-message octets into the transcript (§4.4.1: the message including its
    /// 4-octet header, excluding record framing).
    public mutating func append(_ bytes: [UInt8]) {
        switch hasher {
            case .sha256(var sha):
                sha.update(data: bytes)
                hasher = .sha256(sha)
            case .sha384(var sha):
                sha.update(data: bytes)
                hasher = .sha384(sha)
        }
    }

    /// The transcript hash over everything appended so far — non-destructive, so the schedule
    /// can derive at any §7.1 point while the transcript keeps running.
    public var currentHash: [UInt8] {
        switch hasher {
            case .sha256(let sha):
                Array(sha.finalize())
            case .sha384(let sha):
                Array(sha.finalize())
        }
    }

    /// §4.4.1's HelloRetryRequest replacement: the transcript so far (ClientHello1) collapses to
    /// the synthetic `message_hash` message `254 ∥ 00 00 Hash.length ∥ Hash(ClientHello1)`, and
    /// accumulation restarts from there (HRR, ClientHello2, … are then ``append``ed as usual).
    public mutating func collapseForHelloRetry() {
        let digest = currentHash
        var replacement = Self(hash)
        replacement.append([Self.messageHashType, 0, 0, UInt8(truncatingIfNeeded: digest.count)])
        replacement.append(digest)
        self = replacement
    }
}
