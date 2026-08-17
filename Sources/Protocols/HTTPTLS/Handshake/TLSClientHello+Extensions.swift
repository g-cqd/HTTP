//
//  TLSClientHello+Extensions.swift
//  HTTPTLS
//
//  RFC 8446 §4.2 — the per-extension field parsers behind ``TLSClientHello``'s dispatch.
//  Each enforces its own §4.2.x vector bounds; recognized-but-unimplemented extensions
//  (status_request, padding, session_ticket, …) are accepted with their bodies unexamined —
//  §4.1.2 lets a server that does not IMPLEMENT an extension treat it as absent, and skipping
//  malformed bodies of ignored extensions matches every mainstream stack.
//

extension TLSClientHello {
    /// Dispatches one recognized extension to its parser (positional rules already enforced).
    mutating func applyExtension(
        _ type: TLSExtensionType, data: ArraySlice<UInt8>
    ) throws(TLSHandshakeError) {
        var reader = TLSHandshakeReader(data)
        switch type {
            case .serverName:
                try parseServerName(&reader)
            case .supportedGroups:
                supportedGroups = try reader.u16List("supported_groups")
                    .map { TLSNamedGroup(rawValue: $0) }
            case .signatureAlgorithms:
                signatureAlgorithms = try reader.u16List("signature_algorithms")
                    .map { TLSSignatureScheme(rawValue: $0) }
            case .signatureAlgorithmsCert:
                signatureAlgorithmsCert = try reader.u16List("signature_algorithms_cert")
                    .map { TLSSignatureScheme(rawValue: $0) }
            case .alpn:
                try parseAlpn(&reader)
            case .recordSizeLimit:
                recordSizeLimit = Int(try reader.u16("record_size_limit"))  // RFC 8449 §4
            default:
                try applyKeyExchangeExtension(type, reader: &reader)
                return  // end checks live with the second dispatch half
        }
        try reader.expectEnd(of: "extension \(type.rawValue)")
    }

    /// The key-exchange half of the dispatch (§4.2.1/§4.2.2/§4.2.8–§4.2.11).
    private mutating func applyKeyExchangeExtension(
        _ type: TLSExtensionType, reader: inout TLSHandshakeReader
    ) throws(TLSHandshakeError) {
        switch type {
            case .supportedVersions:
                try parseSupportedVersions(&reader)
            case .keyShare:
                try parseKeyShares(&reader)
            case .pskKeyExchangeModes:
                let modes = try reader.vector8("psk_key_exchange_modes")
                guard !modes.isEmpty else {
                    throw .malformed("psk_key_exchange_modes empty")  // §4.2.9 <1..255>
                }
                pskKeyExchangeModes = [UInt8](modes)
            case .preSharedKey:
                try parsePreSharedKey(&reader)
            case .earlyData:
                offeredEarlyData = true  // §4.2.10: empty in CH
            case .cookie:
                let value = try reader.vector16("cookie")
                guard !value.isEmpty else {
                    throw .malformed("cookie empty")  // §4.2.2 <1..2^16-1>
                }
                cookie = [UInt8](value)
            default:
                return  // recognized, permitted, unimplemented — treated as absent (§4.1.2)
        }
        try reader.expectEnd(of: "extension \(type.rawValue)")
    }

    /// RFC 6066 §3 `server_name`: a ServerNameList with at most one `host_name`.
    private mutating func parseServerName(
        _ reader: inout TLSHandshakeReader
    ) throws(TLSHandshakeError) {
        var list = TLSHandshakeReader(try reader.vector16("server_name_list"))
        while !list.isAtEnd {
            let nameType = try list.byte("server_name type")
            let name = try list.vector16("server_name")
            guard nameType == 0 else {
                continue  // not host_name — RFC 6066 lets unknown name types pass
            }
            guard serverName == nil else {
                throw .malformed("server_name repeated")  // RFC 6066 §3: at most one per type
            }
            guard !name.isEmpty, let host = String(validating: Array(name), as: UTF8.self) else {
                throw .malformed("server_name host")
            }
            serverName = host
        }
    }

    /// RFC 7301 §3.1 `application_layer_protocol_negotiation`: nonempty names, 1..255 octets.
    private mutating func parseAlpn(
        _ reader: inout TLSHandshakeReader
    ) throws(TLSHandshakeError) {
        var list = TLSHandshakeReader(try reader.vector16("alpn protocol_name_list"))
        var protocols: [String] = []
        while !list.isAtEnd {
            let name = try list.vector8("alpn protocol_name")
            guard !name.isEmpty, let value = String(validating: Array(name), as: UTF8.self)
            else {
                throw .malformed("alpn protocol_name")  // RFC 7301: <1..255>
            }
            protocols.append(value)
        }
        guard !protocols.isEmpty else {
            throw .malformed("alpn protocol_name_list empty")  // RFC 7301 <2..2^16-1>
        }
        alpnProtocols = protocols
    }

    /// §4.2.1 `supported_versions` (ClientHello form): 2..254 octets of `uint16` versions.
    private mutating func parseSupportedVersions(
        _ reader: inout TLSHandshakeReader
    ) throws(TLSHandshakeError) {
        let body = try reader.vector8("supported_versions")
        guard !body.isEmpty, body.count.isMultiple(of: 2) else {
            throw .malformed("supported_versions")  // §4.2.1 <2..254>
        }
        var versions: [UInt16] = []
        versions.reserveCapacity(body.count / 2)
        var cursor = body.startIndex
        while cursor < body.endIndex {
            versions.append(UInt16(body[cursor]) << 8 | UInt16(body[cursor + 1]))
            cursor += 2
        }
        supportedVersions = versions
    }

    /// §4.2.8 `key_share`: `client_shares<0..2^16-1>` — empty is legal (it requests HRR);
    /// duplicate groups are not ("MUST NOT offer multiple KeyShareEntry values for the same
    /// group" — this server checks, as §4.2.8 invites).
    private mutating func parseKeyShares(
        _ reader: inout TLSHandshakeReader
    ) throws(TLSHandshakeError) {
        var list = TLSHandshakeReader(try reader.vector16("client_shares"))
        var shares: [TLSKeyShareEntry] = []
        var groups = Set<UInt16>()
        while !list.isAtEnd {
            let group = try list.u16("key_share group")
            let keyExchange = try list.vector16("key_exchange")
            guard !keyExchange.isEmpty else {
                throw .malformed("key_exchange empty")  // §4.2.8 <1..2^16-1>
            }
            guard groups.insert(group).inserted else {
                throw .illegalParameter("duplicate key_share group")  // §4.2.8
            }
            shares.append(
                TLSKeyShareEntry(
                    group: TLSNamedGroup(rawValue: group), keyExchange: [UInt8](keyExchange)
                )
            )
        }
        keyShares = shares
    }

    /// §4.2.11 `pre_shared_key`: identities, binders, and the §4.2.11.2 truncation offset.
    ///
    /// The reader's indices are ABSOLUTE into the raw message buffer (every slice shares its
    /// base), so the binders vector's start position IS the truncated-message length.
    private mutating func parsePreSharedKey(
        _ reader: inout TLSHandshakeReader
    ) throws(TLSHandshakeError) {
        var identities: [TLSPreSharedKeyIdentity] = []
        var identityList = TLSHandshakeReader(try reader.vector16("psk identities"))
        while !identityList.isAtEnd {
            let identity = try identityList.vector16("psk identity")
            guard !identity.isEmpty else {
                throw .malformed("psk identity empty")  // §4.2.11 <1..2^16-1>
            }
            let age = try identityList.u32("obfuscated_ticket_age")
            identities.append(
                TLSPreSharedKeyIdentity(identity: [UInt8](identity), obfuscatedTicketAge: age)
            )
        }
        guard !identities.isEmpty else {
            throw .malformed("psk identities empty")  // §4.2.11 <7..2^16-1>
        }
        let truncatedLength = reader.index  // the binders vector begins here (§4.2.11.2)
        var binders: [[UInt8]] = []
        var binderList = TLSHandshakeReader(try reader.vector16("psk binders"))
        while !binderList.isAtEnd {
            let binder = try binderList.vector8("psk binder")
            guard binder.count >= 32 else {
                throw .malformed("psk binder shorter than 32")  // §4.2.11 <32..255>
            }
            binders.append([UInt8](binder))
        }
        guard !binders.isEmpty else {
            throw .malformed("psk binders empty")  // §4.2.11 <33..2^16-3>
        }
        preSharedKey = TLSPreSharedKeyOffer(
            identities: identities,
            binders: binders,
            truncatedMessageLength: truncatedLength
        )
    }
}
