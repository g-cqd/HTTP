//
//  RFC8448HelloRetry.swift
//  HTTPTLSTests
//
//  RFC 8448 §5 — the HelloRetryRequest trace's key-schedule steps: the §4.4.1
//  message_hash transcript collapse, the P-256 ECDHE feed, and the §7.1 chain through the
//  application traffic secrets.
//  Byte-exact values MACHINE-EXTRACTED from the RFC 8448 text (rfc-editor.org/rfc/rfc8448.txt):
//  every labeled “name (N octets): hex” block of the trace was parsed with its octet count
//  asserted against the hex, so no vector octet was ever hand-typed. Regeneration is a rerun
//  of the same extraction; the RFC text is the single source of truth.
//

/// The RFC 8448 §5 “HelloRetryRequest” trace values (byte-exact, machine-extracted).
enum RFC8448HelloRetry {
    /// RFC 8448: {client} create an ephemeral P-256 key pair — “private key” (32 octets).
    static let clientP256PrivateKey = RFC8448Hex.bytes(
        """
        ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39
        """
    )

    /// RFC 8448: {client} create an ephemeral P-256 key pair — “public key” (65 octets).
    static let clientP256PublicKey = RFC8448Hex.bytes(
        """
        04a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f01
        51812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e80657
        80
        """
    )

    /// RFC 8448: {server} create an ephemeral P-256 key pair — “private key” (32 octets).
    static let serverP256PrivateKey = RFC8448Hex.bytes(
        """
        8c510601f9765bfb8ed693449a48989859b5cfa879cb9f5443c41c5ff10634ed
        """
    )

    /// RFC 8448: {server} create an ephemeral P-256 key pair — “public key” (65 octets).
    static let serverP256PublicKey = RFC8448Hex.bytes(
        """
        04583e054b7a66672ae020ad9d2686fcc85b5ad41a134a0f03ee72b893052bd8
        5b4c8de6776f5b04ac07d83540eab3e3d9c547bc6528c4317d294686093a6cad
        7d
        """
    )

    /// RFC 8448: {client} construct a ClientHello handshake message — “ClientHello” (180 octets).
    static let clientHello1 = RFC8448Hex.bytes(
        """
        010000b00303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee92
        58a346677b6f000006130113031302010000810000000b000900000673657276
        6572ff01000100000a00080006001d00170018003300260024001d0020e8e8e3
        f3b93a25ed97a14a7dcacb8a272c6288e585c6484d05262fcad062ad1f002b00
        03020304000d0020001e04030503060302030804080508060401050106010201
        0402050206020202002d00020101001c00024001
        """
    )

    /// RFC 8448: {server} construct a ServerHello handshake message — “ServerHello” (176 octets).
    static let helloRetryRequest = RFC8448Hex.bytes(
        """
        020000ac0303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e
        09e2c8a8339c001301000084003300020017002c0074007271dcd04bb88bc318
        9119398a00000000eefafc76c146b823b096f8aacad365dd0030953f4edf6256
        36e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d
        6e50781b5eda4aa15b0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0c
        af571fb2b7cff0f934b0002b00020304
        """
    )

    /// RFC 8448: {client} construct a ClientHello handshake message — “ClientHello” (512 octets).
    static let clientHello2 = RFC8448Hex.bytes(
        """
        010001fc0303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee92
        58a346677b6f000006130113031302010001cd0000000b000900000673657276
        6572ff01000100000a00080006001d001700180033004700450017004104a6da
        7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f01518126
        77c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780002b
        0003020304000d0020001e040305030603020308040805080604010501060102
        010402050206020202002c0074007271dcd04bb88bc3189119398a00000000ee
        fafc76c146b823b096f8aacad365dd0030953f4edf625636e5f21bb2e23fcc65
        4b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b
        0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934
        b0002d00020101001c00024001001500af000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        """
    )

    /// RFC 8448: {server} construct a ServerHello handshake message — “ServerHello” (123 octets).
    static let serverHello = RFC8448Hex.bytes(
        """
        020000770303bb341d847fd789c47c387172dc0c9bf147fccacb5043d86ca4c5
        98d3ff571b9800130100004f003300450017004104583e054b7a66672ae020ad
        9d2686fcc85b5ad41a134a0f03ee72b893052bd85b4c8de6776f5b04ac07d835
        40eab3e3d9c547bc6528c4317d294686093a6cad7d002b00020304
        """
    )

    /// RFC 8448: {server} extract secret "early" — “secret” (32 octets).
    static let earlySecret = RFC8448Hex.bytes(
        """
        33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
        """
    )

    /// RFC 8448: {server} extract secret "handshake" — “IKM” (32 octets).
    static let ecdheSharedSecret = RFC8448Hex.bytes(
        """
        c142ce13ca11b5c2233652e63ad3d97844f1621fbfb9de69d547dc8fedeabeb4
        """
    )

    /// RFC 8448: {server} extract secret "handshake" — “secret” (32 octets).
    static let handshakeSecret = RFC8448Hex.bytes(
        """
        ce022e5e6e81e50736d773f2d3adfce8220d049bf510f0dbfac927ef4243b148
        """
    )

    /// RFC 8448: {server} derive secret "tls13 c hs traffic" — “hash” (32 octets).
    static let helloTranscriptHash = RFC8448Hex.bytes(
        """
        8aa8e828ec2f8a884fec95a3139de01c15a3daa7ff5bfc3f4bfcc21b438d7bf8
        """
    )

    /// RFC 8448: {server} derive secret "tls13 c hs traffic" — “expanded” (32 octets).
    static let clientHandshakeTrafficSecret = RFC8448Hex.bytes(
        """
        158aa7ab8855073582b41d674b4055cabcc534728f659314861b4e08e2011566
        """
    )

    /// RFC 8448: {server} derive secret "tls13 s hs traffic" — “expanded” (32 octets).
    static let serverHandshakeTrafficSecret = RFC8448Hex.bytes(
        """
        3403e781e2af7b6508da28574f6e95a1abf162de83a97927c37672a4a0cef8a1
        """
    )

    /// RFC 8448: {server} extract secret "master" — “secret” (32 octets).
    static let masterSecret = RFC8448Hex.bytes(
        """
        1131545d0baf79ddce9b87f06945781a57dd18ef378dcd2060f8f9a569027ed8
        """
    )

    /// RFC 8448: {server} derive write traffic keys for handshake data — “key expanded” (16 octets).
    static let serverHandshakeKey = RFC8448Hex.bytes(
        """
        4646bfac1712c426cd78d8a24a8a6f6b
        """
    )

    /// RFC 8448: {server} derive write traffic keys for handshake data — “iv expanded” (12 octets).
    static let serverHandshakeIV = RFC8448Hex.bytes(
        """
        c7d395c08d62f297d13768ea
        """
    )

    /// RFC 8448: {server} send handshake record — “payload” (645 octets).
    static let serverFlight = RFC8448Hex.bytes(
        """
        080000180016000a0008000600170018001d001c00024001000000000b0001b9
        000001b50001b0308201ac30820115a003020102020102300d06092a864886f7
        0d01010b0500300e310c300a06035504031303727361301e170d313630373330
        3031323335395a170d3236303733303031323335395a300e310c300a06035504
        03130372736130819f300d06092a864886f70d010101050003818d0030818902
        818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a24
        61eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187
        a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0
        461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f
        7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404
        030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b90
        8c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172
        f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608c
        cae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759
        409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400
        8033ab13d4462707231b5dcae6c8190b63d1dabc74f28c395370da0b07e5b830
        66d0246a31acd95df475bfd799a4a70d33ad93d3a317a9b2c0d237a5685b219e
        774112e391a247607d1aeff1bbd0a39f382ee1a5fe88ae99ec59228e6497e45d
        48ce275a6d5ef40d169fb6f9d33b052ed3dcdd6b5a48baafffbcb290128415bd
        38140000208863e6bfb0420a927fa27f34336a70ae426e968e3eb884945b9685
        6dba3976d1
        """
    )

    /// RFC 8448: {server} send handshake record — “complete record” (667 octets).
    static let serverFlightRecord = RFC8448Hex.bytes(
        """
        170303029699bee20baf5b7fc727bfab6223928a381e6d0cf9c4da653f9d2a7b
        23f7de11cce842d5cf75631763450ffb8b0cc1d238e658af7a12adc86243114a
        b14a1da2fae42621ce483fb6242eabfaad52566b02b31d2eddedefeb80e66a99
        00d5f973b40c4fdf74719ecf1b68d7f9c3b6ceb903ca13dd1bb8f8187ae33417
        e1d152522c5822a1a03ad52c838c55953d610222874cce8e1790b229a2aa0b53
        c8d377ee720182951dc6181dc5d90bd1f0105ed1e84aa5f75957c6661897079e
        5ea5007449e3197bdc7c9beeedddeafdd844afa5c315ecfe65e576afe9098128
        80620ec7048b42d7f5c78d76f299d6d82534bdd8f512febc0ed3814aca470cd8
        000d3e1cb9962b052fbb950df683a52c2ba77ed3713b122937a6e5170964e2ab
        7969dcd980b3db9b458da7603124d6dc005e4d6e04b4d0c4baf3275db827dbba
        0a6db09672171fc057b3851d7e026841e2978fbd2346bbefdd0376bb1108fe9a
        cc92189f5650aa5e85d8e8c7b67ac510dba003d3d7e16350bb66d45013efd44c
        9b607c0d318c4c7d1a1f5cbc57e20611804e3787d7b4a4b5f08ed8fd70bdaead
        e02260b12ab842ef690b4a3ee7911e841b374ecd5ebbbc2a54d047b600336dd7
        d0c88b4bc10e58ee6cb656de7247fa20d8e91deb84628608cf80615b62e96c14
        91c7ac3755eb6901405d3474fe1ac79d106a0cee56c2577fc88480f96cb6b8c6
        81b7b68b53c146093908f350888175bdfb0b1e31ad61e30ba0adfe6d223aa03c
        0783b5001a57587c328a9afcfcfb978d1cd4328f7d9d60530e630befd96c0c81
        6ee20b0100768ae2a6df51fc68f172740a79af11398ee3be1252491fa9c69347
        9e877f94ab7c5f8cad480203e6ab7b87dd71e8a0729113df17f5eee86ce108d1
        d72007ec1cd13c85a6c149621e77b7d78d805a30f0be030c315e54
        """
    )

    /// RFC 8448: {server} derive secret "tls13 c ap traffic" — “hash” (32 octets).
    static let serverFinishedTranscriptHash = RFC8448Hex.bytes(
        """
        50f63cbf36b0dd049e7a0ba27d6455745ea2aaac54bb167f9950b2b7ce9509da
        """
    )

    /// RFC 8448: {server} derive secret "tls13 c ap traffic" — “expanded” (32 octets).
    static let clientApplicationTrafficSecret = RFC8448Hex.bytes(
        """
        75ecf4b972525aa0dcd057c9944d4cd5d82671d8843141d7dc2a4ff15a21dc51
        """
    )

    /// RFC 8448: {server} derive secret "tls13 s ap traffic" — “expanded” (32 octets).
    static let serverApplicationTrafficSecret = RFC8448Hex.bytes(
        """
        5c74f87df04225db0f8209c9de6429e49435fdefa7cad61864874d12f31cfc8d
        """
    )

    /// RFC 8448: {server} derive secret "tls13 exp master" — “expanded” (32 octets).
    static let exporterMasterSecret = RFC8448Hex.bytes(
        """
        7c06d3ae106a3a374ace4837b3985cac67780a6e2c5c04b58319d584df09d223
        """
    )
}
