//
//  BodyEncoder.swift
//  HTTPCore
//
//  The outbound half of the typed body-codec seam (Phase 2.3): an encoder turns a typed value into
//  response-body bytes plus the `Content-Type` they carry. Conform a custom type (a JSON `Encodable`
//  codec in a Foundation-importing layer) and use ``ServerResponse/encoded(_:using:status:)``; the
//  built-in `.json(_:)` / `.text(_:)` constructors remain the ready-made byte / string encoder paths.
//

/// Encodes a typed ``Value`` into response-body bytes and the `Content-Type` they carry (the outbound
/// body-codec seam, RFC 9110 §8.3).
public protocol BodyEncoder<Value>: Sendable {
    /// The value this encoder serializes.
    associatedtype Value

    /// The `Content-Type` the encoded bytes carry.
    var contentType: String { get }

    /// Encodes `value` into response-body bytes, throwing on a value it cannot serialize.
    func encode(_ value: Value) throws -> [UInt8]
}
