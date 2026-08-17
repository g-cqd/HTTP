//
//  RFC8448Resumed.swift
//  HTTPTLSTests
//
//  RFC 8448 §4 — the Resumed 0-RTT trace, as far as it exercises Phase 3a machinery: the
//  PSK-fed early secret, the §4.2.11.2 binder chain, the client early traffic secret and
//  its §7.3 keys, and the protected 0-RTT application record.
//  Byte-exact values MACHINE-EXTRACTED from the RFC 8448 text (rfc-editor.org/rfc/rfc8448.txt):
//  every labeled “name (N octets): hex” block of the trace was parsed with its octet count
//  asserted against the hex, so no vector octet was ever hand-typed. Regeneration is a rerun
//  of the same extraction; the RFC text is the single source of truth.
//

/// The RFC 8448 §4 “Resumed 0-RTT Handshake” early-secret trace values (byte-exact).
enum RFC8448Resumed {
    /// RFC 8448: {client} extract secret "early" — “IKM” (32 octets).
    static let pskInputKeyMaterial = RFC8448Hex.bytes(
        """
        4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3
        """
    )

    /// RFC 8448: {client} extract secret "early" — “secret” (32 octets).
    static let earlySecret = RFC8448Hex.bytes(
        """
        9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c
        """
    )

    /// RFC 8448: {client} send handshake record — “payload” (512 octets): the FULL
    /// ClientHello including the §4.2.11.2 binders (the “construct” block prints it
    /// truncated before the binder list, which is what `clientHelloBinderPrefix` holds).
    static let clientHello = RFC8448Hex.bytes(
        """
        010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc41
        9d7876487d95000006130113031302010001cd0000000b000900000673657276
        6572ff01000100000a00140012001d0017001800190100010101020103010400
        3300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe
        051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603
        020308040805080604010501060102010402050206020202002d00020101001c
        0002400100150057000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        2900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a
        34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a98211
        7283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3
        664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b
        3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c6
        21a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb002120
        3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d
        """
    )

    /// RFC 8448: {client} calculate PSK binder — “ClientHello prefix” (477 octets).
    static let clientHelloBinderPrefix = RFC8448Hex.bytes(
        """
        010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc41
        9d7876487d95000006130113031302010001cd0000000b000900000673657276
        6572ff01000100000a00140012001d0017001800190100010101020103010400
        3300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe
        051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603
        020308040805080604010501060102010402050206020202002d00020101001c
        0002400100150057000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        2900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a
        34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a98211
        7283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3
        664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b
        3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c6
        21a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb
        """
    )

    /// RFC 8448: {client} calculate PSK binder — “binder hash” (32 octets).
    static let binderTranscriptHash = RFC8448Hex.bytes(
        """
        63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14
        """
    )

    /// RFC 8448: {client} calculate PSK binder — “PRK” (32 octets).
    static let binderKey = RFC8448Hex.bytes(
        """
        69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256
        """
    )

    /// RFC 8448: {client} calculate PSK binder — “expanded” (32 octets).
    static let binderFinishedKey = RFC8448Hex.bytes(
        """
        5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa
        """
    )

    /// RFC 8448: {client} calculate PSK binder — “finished” (32 octets).
    static let binderValue = RFC8448Hex.bytes(
        """
        3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d
        """
    )

    /// RFC 8448: {client} derive secret "tls13 c e traffic" — “hash” (32 octets).
    static let clientHelloTranscriptHash = RFC8448Hex.bytes(
        """
        08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913
        """
    )

    /// RFC 8448: {client} derive secret "tls13 c e traffic" — “expanded” (32 octets).
    static let clientEarlyTrafficSecret = RFC8448Hex.bytes(
        """
        3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62
        """
    )

    /// RFC 8448: {client} derive secret "tls13 e exp master" — “expanded” (32 octets).
    static let earlyExporterMasterSecret = RFC8448Hex.bytes(
        """
        b2026866610937d7423e5be90862ccf24c0e6091186d34f812089ff5be2ef7df
        """
    )

    /// RFC 8448: {client} derive write traffic keys for early application data — “key expanded” (16 octets).
    static let earlyWriteKey = RFC8448Hex.bytes(
        """
        920205a5b7bf2115e6fc5c2942834f54
        """
    )

    /// RFC 8448: {client} derive write traffic keys for early application data — “iv expanded” (12 octets).
    static let earlyWriteIV = RFC8448Hex.bytes(
        """
        6d475f0993c8e564610db2b9
        """
    )

    /// RFC 8448: {client} send application_data record — “payload” (6 octets).
    static let earlyApplicationData = RFC8448Hex.bytes(
        """
        414243444546
        """
    )

    /// RFC 8448: {client} send application_data record — “complete record” (28 octets).
    static let earlyApplicationDataRecord = RFC8448Hex.bytes(
        """
        1703030017ab1df420e75c457a7cc5d2844f76d5aee4b4edbf049be0
        """
    )
}
