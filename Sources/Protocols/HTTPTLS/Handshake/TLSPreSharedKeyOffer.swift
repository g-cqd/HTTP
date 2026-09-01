//
//  TLSPreSharedKeyOffer.swift
//  HTTPTLS
//
//  RFC 8446 §4.2.11 — the ClientHello `pre_shared_key` extension: the identity list, the
//  binder list, and the §4.2.11.2 truncation length. The binders authenticate
//  `Truncate(ClientHello)` — the message "up to (and including) the identities in the
//  PreSharedKeyExtension", i.e. everything before the binders vector's own length prefix — so
//  the parser records that boundary as an offset into the RAW message while it still knows it.
//

/// The parsed ClientHello `pre_shared_key` offer (RFC 8446 §4.2.11).
struct TLSPreSharedKeyOffer: Sendable, Equatable {
    /// The offered identities, in the client's preference order (§4.2.11).
    let identities: [TLSPreSharedKeyIdentity]
    /// The binder values, one per identity, in the same order (§4.2.11.2).
    let binders: [[UInt8]]
    /// How many octets of the RAW handshake message (header included) precede the binders
    /// vector — the length of `Truncate(ClientHello)` per §4.2.11.2.
    let truncatedMessageLength: Int
}
