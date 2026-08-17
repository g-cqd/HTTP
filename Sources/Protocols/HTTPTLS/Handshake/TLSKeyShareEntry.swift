//
//  TLSKeyShareEntry.swift
//  HTTPTLS
//
//  RFC 8446 §4.2.8 — one `KeyShareEntry`: a named group and its opaque `key_exchange` octets.
//  Share VALIDATION (§4.2.8.2 lengths, on-curve checks) happens where the share is used, in
//  ``TLSKeyExchange`` — entries for unimplemented groups must survive parsing so negotiation
//  can skip them.
//

/// One ClientHello `KeyShareEntry` (RFC 8446 §4.2.8).
struct TLSKeyShareEntry: Sendable, Equatable {
    /// The share's group (§4.2.8; may be unimplemented — negotiation skips it).
    let group: TLSNamedGroup
    /// The opaque `key_exchange` octets (validated by ``TLSKeyExchange`` when selected).
    let keyExchange: [UInt8]
}
