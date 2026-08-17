//
//  TLSRecordLimits.swift
//  HTTPTLS
//
//  RFC 8446 §5.1/§5.2 — the record-layer length constants. TLS 1.3 caps a plaintext fragment at
//  2^14 octets, a protected record body at 2^14 + 256 (fragment + inner type + up to 255 octets
//  of AEAD expansion), and a decrypted `TLSInnerPlaintext` at 2^14 + 1; anything larger is a
//  `record_overflow` alert. The 5-octet header and the frozen legacy version octets live here
//  with them so every parser cites one table.
//

/// The RFC 8446 §5 record-layer length and framing constants.
public enum TLSRecordLimits {
    /// The maximum `TLSPlaintext.fragment` length — 2^14 octets (§5.1).
    public static let maxPlaintextLength = 16_384
    /// The maximum `TLSCiphertext.encrypted_record` length — 2^14 + 256 octets (§5.2).
    public static let maxCiphertextLength = 16_384 + 256
    /// The maximum decrypted `TLSInnerPlaintext` length — 2^14 + 1 octets (§5.2).
    public static let maxInnerPlaintextLength = 16_384 + 1
    /// The record header: type (1) + legacy version (2) + length (2) octets (§5.1).
    public static let headerLength = 5
    /// The frozen `legacy_record_version` 0x0303 every sender writes (§5.1; receivers ignore
    /// the field entirely — the initial ClientHello MAY carry 0x0301).
    public static let legacyVersionMajor: UInt8 = 0x03
    /// The minor octet of the frozen 0x0303 legacy version (§5.1).
    public static let legacyVersionMinor: UInt8 = 0x03
}
