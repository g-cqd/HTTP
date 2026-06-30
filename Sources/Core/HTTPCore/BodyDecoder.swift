//
//  BodyDecoder.swift
//  HTTPCore
//
//  The inbound half of the typed body-codec seam (Phase 2.3): a decoder turns a request body's bytes —
//  with the request's content type, for codecs that need it (e.g. multipart's boundary) — into a typed
//  value. Conform a custom type (a JSON `Decodable` codec in a Foundation-importing layer, say) to plug
//  it into ``RequestBody/decode(using:for:)``. The form and multipart decoders ship here, zero-dependency.
//

/// Decodes a request body's bytes into a typed ``Value`` (the inbound body-codec seam, Phase 2.3).
public protocol BodyDecoder<Value>: Sendable {
    /// The value this decoder produces.
    associatedtype Value

    /// Decodes `body` into a ``Value``, consulting `contentType` for codecs that need it (e.g. a
    /// multipart boundary); throws on malformed or unsupported input.
    func decode(_ body: [UInt8], contentType: String?) throws -> Value
}
