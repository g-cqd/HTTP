//
//  RFC8448Compat.swift
//  HTTPTLSTests
//
//  RFC 8448 §7 — Compatibility Mode: the unencrypted change_cipher_spec record both peers
//  interleave with the handshake (Appendix D.4), which the record layer must drop.
//  Byte-exact values MACHINE-EXTRACTED from the RFC 8448 text (rfc-editor.org/rfc/rfc8448.txt):
//  every labeled “name (N octets): hex” block of the trace was parsed with its octet count
//  asserted against the hex, so no vector octet was ever hand-typed. Regeneration is a rerun
//  of the same extraction; the RFC text is the single source of truth.
//

/// The RFC 8448 §7 “Compatibility Mode” change_cipher_spec record (byte-exact).
enum RFC8448Compat {
    /// RFC 8448: {server} send change_cipher_spec record — “complete record” (6 octets).
    static let changeCipherSpecRecord = RFC8448Hex.bytes(
        """
        140303000101
        """
    )

    /// RFC 8448: {client} send handshake record — “complete record” (229 octets).
    static let clientHelloRecord = RFC8448Hex.bytes(
        """
        16030100e0010000dc03034e640a3f2c2738f09c9418bd78edccd7559d053119
        9276d4d92a0e9ee9d77d0920a80c165581a8e0d06c0018d54d3a06dd32cfd405
        1eb026fad3fd0ba99269e6ef00061301130313020100008d0000000b00090000
        06736572766572ff01000100000a00140012001d001700180019010001010102
        01030104003300260024001d00208e7292cf3056dbb0d25fcbe55c107dc9bbf8
        3dd9708f39203ba341249a7d9b63002b0003020304000d0020001e0403050306
        03020308040805080604010501060102010402050206020202002d0002010100
        1c00024001
        """
    )

    /// RFC 8448: {server} send handshake record — “complete record” (127 octets).
    static let serverHelloRecord = RFC8448Hex.bytes(
        """
        160303007a020000760303e5dd5948c435f7a38f0f0130708dc322d9df09abd4
        838117c183a7bb6d994f2c20a80c165581a8e0d06c0018d54d3a06dd32cfd405
        1eb026fad3fd0ba99269e6ef130100002e00330024001d00203e30f0f4ba551a
        fd62768341175f5265e4daf0c8841617aa4fafdd2142320c22002b00020304
        """
    )
}
