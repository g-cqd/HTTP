//
//  TLSEncryptedExtensions.swift
//  HTTPTLS
//
//  RFC 8446 §4.3.1 — the EncryptedExtensions encoder: the server's non-key-exchange answers,
//  first flight under the handshake keys. Emission order is fixed to the RFC 8448 traces'
//  order — supported_groups, record_size_limit, server_name, then ALPN — so the byte-exact
//  replay gates hold. `early_data` is NEVER emitted: this server rejects 0-RTT by §4.2.10's
//  first option (ignore the extension, return a 1-RTT response, skip undecryptable records).
//

/// The EncryptedExtensions encoder (RFC 8446 §4.3.1).
enum TLSEncryptedExtensionsEncoder {
    /// Encodes the EncryptedExtensions message.
    ///
    /// - Parameters:
    ///   - supportedGroupsHint: The §4.2.7 hint list ("the server MAY send it... to indicate
    ///     the groups it prefers"); empty emits nothing.
    ///   - recordSizeLimit: Our RFC 8449 receive limit, echoed only when the client offered
    ///     the extension (negotiation requires both sides).
    ///   - acknowledgeServerName: Whether to append the empty `server_name` ack (RFC 6066 §3:
    ///     the server "SHALL include an extension of type 'server_name'... empty").
    ///   - alpnProtocol: The selected ALPN protocol (RFC 7301 §3.2), when negotiated.
    /// - Returns: The framed EncryptedExtensions message octets.
    static func encryptedExtensions(
        supportedGroupsHint: [TLSNamedGroup],
        recordSizeLimit: Int?,
        acknowledgeServerName: Bool,
        alpnProtocol: String?
    ) -> [UInt8] {
        TLSHandshakeBuilder.message(.encryptedExtensions) { message in
            message.vector16 { extensions in
                if !supportedGroupsHint.isEmpty {
                    extensions.extensionField(.supportedGroups) { body in
                        body.vector16 { list in
                            for group in supportedGroupsHint {
                                list.u16(group.rawValue)  // §4.2.7
                            }
                        }
                    }
                }
                if let recordSizeLimit {
                    extensions.extensionField(.recordSizeLimit) { body in
                        body.u16(UInt16(truncatingIfNeeded: recordSizeLimit))  // RFC 8449 §4
                    }
                }
                if acknowledgeServerName {
                    extensions.extensionField(.serverName) { _ in
                        // RFC 6066 §3: the acknowledgement is an EMPTY extension
                    }
                }
                if let alpnProtocol {
                    extensions.extensionField(.alpn) { body in
                        body.vector16 { list in
                            list.vector8 { $0.raw(alpnProtocol.utf8) }  // RFC 7301 §3.2
                        }
                    }
                }
            }
        }
    }
}
