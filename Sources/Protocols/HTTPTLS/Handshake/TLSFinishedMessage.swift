//
//  TLSFinishedMessage.swift
//  HTTPTLS
//
//  RFC 8446 §4.4.4 — the Finished codec. The body is exactly `verify_data`, `Hash.length`
//  octets of `HMAC(finished_key, Transcript-Hash(...))`; computation and constant-time
//  verification live with ``TLSKeySchedule``/``TLSHashFunction`` — this type only frames.
//

/// The Finished message codec (RFC 8446 §4.4.4).
enum TLSFinishedCodec {
    /// Encodes a Finished message around the computed `verify_data`.
    static func finished(verifyData: [UInt8]) -> [UInt8] {
        TLSHandshakeBuilder.message(.finished) { $0.raw(verifyData) }
    }

    /// Extracts `verify_data`, enforcing the §4.4.4 `Hash.length` body length.
    static func parseVerifyData(
        _ message: TLSHandshakeCoalescer.Message, hash: TLSHashFunction
    ) throws(TLSHandshakeError) -> ArraySlice<UInt8> {
        guard message.body.count == hash.digestByteCount else {
            throw .malformed("Finished verify_data length")  // §4.4.4: Hash.length octets
        }
        return message.body
    }
}
