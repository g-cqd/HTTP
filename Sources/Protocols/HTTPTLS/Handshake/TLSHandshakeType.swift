//
//  TLSHandshakeType.swift
//  HTTPTLS
//
//  RFC 8446 §4 — the `HandshakeType` octet of every handshake message. Only the types a TLS 1.3
//  SERVER can legitimately send or receive are modeled as cases; an unknown octet is a
//  caller-visible parse failure (`unexpected_message`, §6.2), never a trap. The §4.4.1 synthetic
//  `message_hash(254)` never crosses the wire (it exists only inside the transcript) and so is
//  deliberately not a case here — ``TLSTranscriptHash`` owns that octet.
//

/// A handshake message type (RFC 8446 §4's `HandshakeType`).
public enum TLSHandshakeType: UInt8, Sendable, Equatable {
    /// `client_hello(1)` (§4.1.2).
    case clientHello = 1
    /// `server_hello(2)` — also HelloRetryRequest, distinguished by the random (§4.1.3/§4.1.4).
    case serverHello = 2
    /// `new_session_ticket(4)` (§4.6.1).
    case newSessionTicket = 4
    /// `end_of_early_data(5)` (§4.5) — never legitimate here: this server rejects 0-RTT, and a
    /// client whose early data was rejected MUST NOT send it (§4.2.10).
    case endOfEarlyData = 5
    /// `encrypted_extensions(8)` (§4.3.1).
    case encryptedExtensions = 8
    /// `certificate(11)` (§4.4.2).
    case certificate = 11
    /// `certificate_request(13)` (§4.3.2).
    case certificateRequest = 13
    /// `certificate_verify(15)` (§4.4.3).
    case certificateVerify = 15
    /// `finished(20)` (§4.4.4).
    case finished = 20
    /// `key_update(24)` (§4.6.3).
    case keyUpdate = 24
}
