//
//  TLSKeyUpdateMessage.swift
//  HTTPTLS
//
//  RFC 8446 §4.6.3 — the KeyUpdate codec. The one-octet `request_update` field admits exactly
//  two values; "if an implementation receives any other value, it MUST terminate the
//  connection with an 'illegal_parameter' alert" — enforced here, at the decode boundary.
//

/// A KeyUpdate message (RFC 8446 §4.6.3).
enum TLSKeyUpdateMessage: UInt8, Sendable, Equatable {
    /// `update_not_requested(0)` — the sender rekeyed; no response owed.
    case updateNotRequested = 0
    /// `update_requested(1)` — the receiver must answer with its own KeyUpdate (§4.6.3).
    case updateRequested = 1

    /// Encodes this KeyUpdate.
    func encoded() -> [UInt8] {
        TLSHandshakeBuilder.message(.keyUpdate) { $0.u8(rawValue) }
    }

    /// Parses a KeyUpdate, enforcing the §4.6.3 value rule.
    static func parse(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) -> Self {
        var reader = TLSHandshakeReader(message.body)
        let value = try reader.byte("request_update")
        try reader.expectEnd(of: "KeyUpdate")
        guard let update = Self(rawValue: value) else {
            throw .invalidKeyUpdate(value)  // §4.6.3: illegal_parameter
        }
        return update
    }
}
