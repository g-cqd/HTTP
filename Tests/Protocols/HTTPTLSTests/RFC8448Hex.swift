//
//  RFC8448Hex.swift
//  HTTPTLSTests
//
//  The hex decoder behind the machine-extracted RFC 8448 fixtures: multiline hex strings in,
//  octets out. Test-only; a malformed fixture trips the precondition at suite load, which is
//  exactly when a corrupted vector should be caught.
//

/// Decodes the fixtures' multiline hex-string constants into octets.
enum RFC8448Hex {
    /// Converts a hex string (whitespace/newlines ignored) into its octets.
    static func bytes(_ hex: String) -> [UInt8] {
        var octets: [UInt8] = []
        octets.reserveCapacity(hex.utf8.count / 2)
        var pending: UInt8?
        for character in hex {
            guard let value = character.hexDigitValue else {
                precondition(character.isWhitespace, "non-hex character in fixture: \(character)")
                continue
            }
            if let high = pending {
                octets.append(high << 4 | UInt8(truncatingIfNeeded: value))
                pending = nil
            }
            else {
                pending = UInt8(truncatingIfNeeded: value)
            }
        }
        precondition(pending == nil, "odd-length hex fixture")
        return octets
    }
}
