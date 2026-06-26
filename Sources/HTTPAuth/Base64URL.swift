//
//  Base64URL.swift
//  HTTPAuth
//
//  RFC 4648 §5 — unpadded base64url, used to decode the three segments of a JWT (`header.payload.sig`).
//  Trap-free: malformed input yields nil rather than faulting.
//

internal import Foundation

/// Unpadded base64url (RFC 4648 §5) decode/encode for JWT segments.
enum Base64URL {
    /// Decodes an unpadded base64url string to bytes, or nil if malformed.
    static func decode(_ string: String) -> [UInt8]? {
        var standard = string.replacingOccurrences(of: "-", with: "+")
        standard = standard.replacingOccurrences(of: "_", with: "/")
        while standard.count % 4 != 0 {
            standard += "="
        }
        guard let data = Data(base64Encoded: standard) else {
            return nil
        }
        return [UInt8](data)
    }

    /// Encodes bytes as an unpadded base64url string.
    static func encode(_ bytes: [UInt8]) -> String {
        var encoded = Data(bytes).base64EncodedString()
        encoded = encoded.replacingOccurrences(of: "+", with: "-")
        encoded = encoded.replacingOccurrences(of: "/", with: "_")
        while encoded.hasSuffix("=") {
            encoded.removeLast()
        }
        return encoded
    }
}
