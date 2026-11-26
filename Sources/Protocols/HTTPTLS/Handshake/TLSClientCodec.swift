//
//  TLSClientCodec.swift
//  HTTPTLS
//
//  RFC 8446 §4.1.2 / §4.1.3 / §4.3.1 — the ClientHello encoder and the ServerHello and
//  EncryptedExtensions decoders for ``TLSClientConnection``. Bounds-checked over
//  ``TLSHandshakeReader``; never traps.
//

/// Client-side handshake wire codecs (RFC 8446 §4.1.2, §4.1.3, §4.3.1).
enum TLSClientCodec {
    static let legacyVersion: UInt16 = 0x0303
    static let tls13: UInt16 = 0x0304

    /// Everything one ClientHello carries.
    struct HelloParameters {
        let random: [UInt8]
        let sessionID: [UInt8]
        let configuration: TLSClientConfiguration
        let serverName: String?
        let keyShareGroup: TLSNamedGroup
        let keyShareExchange: [UInt8]
        let cookie: [UInt8]?
    }

    /// A parsed ServerHello or HelloRetryRequest (§4.1.3 / §4.1.4).
    struct ParsedServerHello: Sendable, Equatable {
        let random: [UInt8]
        let sessionID: [UInt8]
        let cipherSuite: TLSCipherSuite
        var supportedVersion: UInt16?
        var keyShareGroup: TLSNamedGroup?
        var keyShareExchange: [UInt8]?
        var cookie: [UInt8]?

        var isHelloRetryRequest: Bool {
            random == TLSServerHelloEncoder.helloRetryRequestRandom
        }
    }

    /// The EncryptedExtensions a client acts on (§4.3.1).
    struct ParsedEncryptedExtensions: Sendable, Equatable {
        var alpnProtocol: String?
        var recordSizeLimit: Int?
    }

    /// Encodes a TLS 1.3 `ClientHello` (§4.1.2).
    static func clientHello(_ hello: HelloParameters) -> [UInt8] {
        TLSHandshakeBuilder.message(.clientHello) { body in
            body.clientHelloPrefix(
                version: legacyVersion,
                random: hello.random,
                sessionID: hello.sessionID,
                cipherSuites: hello.configuration.cipherSuites.map(\.rawValue),
                compressionMethods: [0]
            )
            body.vector16 { appendExtensions(hello, into: &$0) }
        }
    }

    private static func appendExtensions(
        _ hello: HelloParameters, into ext: inout TLSHandshakeBuilder
    ) {
        let configuration = hello.configuration
        if let serverName = hello.serverName, !serverName.isEmpty {
            ext.extensionField(.serverName) { sni in  // RFC 6066 §3: one host_name entry
                sni.vector16 { list in
                    list.u8(0)
                    list.vector16 { $0.raw(serverName.utf8) }
                }
            }
        }
        ext.extensionField(.supportedVersions) { versions in versions.vector8 { $0.u16(tls13) } }
        appendU16List(.supportedGroups, configuration.groups.map(\.rawValue), into: &ext)
        appendU16List(
            .signatureAlgorithms,
            configuration.signatureSchemes.map(\.rawValue),
            into: &ext
        )
        if let cookie = hello.cookie {
            ext.extensionField(.cookie) { field in field.vector16 { $0.raw(cookie) } }
        }
        if !configuration.alpnProtocols.isEmpty {
            ext.extensionField(.alpn) { alpn in
                alpn.vector16 { list in
                    for proto in configuration.alpnProtocols {
                        list.vector8 { $0.raw(proto.utf8) }
                    }
                }
            }
        }
        ext.extensionField(.pskKeyExchangeModes) { modes in
            modes.vector8 { $0.u8(TLSClientHello.pskDheKeMode) }
        }
        ext.extensionField(.keyShare) { shares in
            shares.vector16 { list in
                list.u16(hello.keyShareGroup.rawValue)
                list.vector16 { $0.raw(hello.keyShareExchange) }
            }
        }
    }

    private static func appendU16List(
        _ type: TLSExtensionType,
        _ values: [UInt16],
        into ext: inout TLSHandshakeBuilder
    ) {
        ext.extensionField(type) { field in
            field.vector16 { list in
                for value in values {
                    list.u16(value)
                }
            }
        }
    }

    /// Parses a `ServerHello` or `HelloRetryRequest` (§4.1.3 / §4.1.4).
    static func parseServerHello(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) -> ParsedServerHello {
        var reader = TLSHandshakeReader(message.body)
        guard try reader.u16("ServerHello.legacy_version") == legacyVersion else {
            throw .unsupportedVersion
        }
        let random = [UInt8](try reader.slice(32, "ServerHello.random"))
        let sessionID = [UInt8](try reader.vector8("ServerHello.session_id"))
        guard sessionID.count <= 32 else {
            throw .malformed("ServerHello.session_id > 32")
        }
        guard let suite = TLSCipherSuite(rawValue: try reader.u16("ServerHello.cipher_suite"))
        else {
            throw .illegalParameter("unoffered cipher_suite")
        }
        guard try reader.byte("ServerHello.compression_method") == 0 else {
            throw .illegalParameter("non-zero ServerHello compression_method")
        }
        var hello = ParsedServerHello(random: random, sessionID: sessionID, cipherSuite: suite)
        let block = try reader.vector16("ServerHello.extensions")
        try reader.expectEnd(of: "ServerHello")
        let isRetry = hello.isHelloRetryRequest
        try forEachExtension(in: block) { type, ext throws(TLSHandshakeError) in
            switch type {
                case .supportedVersions:
                    hello.supportedVersion = try ext.u16("ServerHello.supported_versions")
                case .keyShare:
                    hello.keyShareGroup = TLSNamedGroup(
                        rawValue: try ext.u16("ServerHello.key_share.group")
                    )
                    if !isRetry {
                        hello.keyShareExchange = [UInt8](
                            try ext.vector16("ServerHello.key_share.exchange")
                        )
                    }
                case .cookie where isRetry:
                    hello.cookie = [UInt8](try ext.vector16("HelloRetryRequest.cookie"))
                    guard hello.cookie?.isEmpty == false else {
                        throw .malformed("empty HelloRetryRequest cookie")
                    }
                case .preSharedKey:
                    _ = try ext.u16("ServerHello.pre_shared_key")
                default:
                    throw .extensionNotPermitted(type)  // §4.1.3: only what the client offered
            }
        }
        return hello
    }

    /// Parses `EncryptedExtensions` (§4.3.1).
    static func parseEncryptedExtensions(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) -> ParsedEncryptedExtensions {
        var reader = TLSHandshakeReader(message.body)
        let block = try reader.vector16("EncryptedExtensions")
        try reader.expectEnd(of: "EncryptedExtensions")
        var parsed = ParsedEncryptedExtensions()
        try forEachExtension(in: block) { type, ext throws(TLSHandshakeError) in
            switch type {
                case .alpn:
                    var list = TLSHandshakeReader(try ext.vector16("EncryptedExtensions.alpn"))
                    let proto = try list.vector8("EncryptedExtensions.alpn.protocol")
                    // RFC 7301 §3.1: the server selects exactly one protocol.
                    try list.expectEnd(of: "EncryptedExtensions.alpn")
                    guard !proto.isEmpty else {
                        throw .malformed("empty ALPN protocol")
                    }
                    guard let name = String(validating: proto, as: UTF8.self) else {
                        throw .malformed("ALPN protocol is not UTF-8")
                    }
                    parsed.alpnProtocol = name
                case .recordSizeLimit:
                    let limit = Int(try ext.u16("EncryptedExtensions.record_size_limit"))
                    guard limit >= 64 else {
                        throw .illegalParameter("record_size_limit below 64")  // RFC 8449 §4
                    }
                    parsed.recordSizeLimit = limit
                default:
                    // Informational (server_name acknowledgement, supported_groups): skipped.
                    _ = try ext.slice(ext.remaining, "informational extension")
            }
        }
        return parsed
    }

    /// Walks an extension block, rejecting duplicates (§4.2) and requiring each body be consumed.
    private static func forEachExtension(
        in block: ArraySlice<UInt8>,
        _ body: (TLSExtensionType, inout TLSHandshakeReader) throws(TLSHandshakeError) -> Void
    ) throws(TLSHandshakeError) {
        var cursor = TLSHandshakeReader(block)
        var seen = Set<TLSExtensionType>()
        while !cursor.isAtEnd {
            let type = TLSExtensionType(rawValue: try cursor.u16("extension type"))
            guard seen.insert(type).inserted else {
                throw .duplicateExtension(type)
            }
            var ext = TLSHandshakeReader(try cursor.vector16("extension body"))
            try body(type, &ext)
            try ext.expectEnd(of: "extension")
        }
    }
}
