//
//  TestClientHello.swift
//  HTTPTLSTests
//
//  A knob-per-field ClientHello builder for the negative battery: every §4.1.2/§4.2 rule the
//  server must enforce needs a hello that VIOLATES it, which no honest client emits. Nil
//  omits an extension; `rawExtensions` injects arbitrary type/data pairs (duplicates,
//  misplaced types); `preSharedKey` appends the §4.2.11 offer last (or wherever
//  `preSharedKeyFirst` puts it, for the must-be-last test).
//

@testable internal import HTTPTLS

/// A fully controllable ClientHello for driving the server machine in tests.
struct TestClientHello {
    /// `legacy_version` (§4.1.2).
    var legacyVersion: UInt16 = 0x0303
    /// The 32-octet client random.
    var random = [UInt8](repeating: 0x11, count: 32)
    /// `legacy_session_id`.
    var sessionID: [UInt8] = []
    /// Offered cipher suites.
    var cipherSuites: [UInt16] = [0x1301, 0x1302, 0x1303]
    /// `legacy_compression_methods`.
    var compression: [UInt8] = [0]
    /// SNI host, nil omits.
    var serverName: String? = "server"
    /// `supported_groups`, nil omits.
    var supportedGroups: [UInt16]? = [0x001D, 0x0017]
    /// `signature_algorithms`, nil omits.
    var signatureAlgorithms: [UInt16]? = [0x0403, 0x0503, 0x0807, 0x0804]
    /// `supported_versions`, nil omits (the Appendix D.2 downgrade case).
    var supportedVersions: [UInt16]? = [0x0304]
    /// `key_share` entries (group, key_exchange), nil omits the extension entirely.
    var keyShares: [(UInt16, [UInt8])]? = []
    /// `psk_key_exchange_modes`, nil omits.
    var pskKeyExchangeModes: [UInt8]? = [1]
    /// ALPN names, nil omits.
    var alpnProtocols: [String]?
    /// `early_data` presence (§4.2.10).
    var offersEarlyData = false
    /// The HRR `cookie`, nil omits.
    var cookie: [UInt8]?
    /// `record_size_limit`, nil omits.
    var recordSizeLimit: UInt16?
    /// Arbitrary extra (type, data) pairs — duplicates and misplaced types for the battery.
    var rawExtensions: [(UInt16, [UInt8])] = []
    /// The §4.2.11 offer: (ticket, obfuscated age) identities + one binder value per identity.
    var preSharedKey: (identities: [([UInt8], UInt32)], binders: [[UInt8]])?
    /// Whether to put `pre_shared_key` FIRST instead of last (the §4.2.11 violation).
    var preSharedKeyFirst = false

    /// Encodes the full handshake message (header included).
    func message() -> [UInt8] {
        TLSHandshakeBuilder.message(.clientHello) { body in
            body.u16(legacyVersion)
            body.raw(random)
            body.vector8 { $0.raw(sessionID) }
            body.vector16 { suites in
                for suite in cipherSuites {
                    suites.u16(suite)
                }
            }
            body.vector8 { $0.raw(compression) }
            body.vector16 { extensions in
                if preSharedKeyFirst {
                    appendPreSharedKey(&extensions)
                }
                appendStandardExtensions(&extensions)
                for (type, data) in rawExtensions {
                    extensions.u16(type)
                    extensions.vector16 { $0.raw(data) }
                }
                if !preSharedKeyFirst {
                    appendPreSharedKey(&extensions)
                }
            }
        }
    }

    /// Wraps a handshake message in an unprotected §5.1 record.
    static func plaintextRecord(_ message: [UInt8]) -> [UInt8] {
        var record: [UInt8] = [
            22, 3, 3,
            UInt8(truncatingIfNeeded: message.count >> 8),
            UInt8(truncatingIfNeeded: message.count)
        ]
        record += message
        return record
    }

    /// The knob-driven ordinary extensions (split across two helpers for the lint
    /// complexity budget).
    private func appendStandardExtensions(_ extensions: inout TLSHandshakeBuilder) {
        appendIdentityExtensions(&extensions)
        appendKeyExchangeExtensions(&extensions)
    }

    /// SNI / groups / schemes / ALPN / record_size_limit.
    private func appendIdentityExtensions(_ extensions: inout TLSHandshakeBuilder) {
        if let serverName {
            extensions.extensionField(.serverName) { body in
                body.vector16 { list in
                    list.u8(0)  // host_name
                    list.vector16 { $0.raw(serverName.utf8) }
                }
            }
        }
        if let supportedGroups {
            extensions.extensionField(.supportedGroups) { body in
                body.vector16 { list in
                    for group in supportedGroups {
                        list.u16(group)
                    }
                }
            }
        }
        if let signatureAlgorithms {
            extensions.extensionField(.signatureAlgorithms) { body in
                body.vector16 { list in
                    for scheme in signatureAlgorithms {
                        list.u16(scheme)
                    }
                }
            }
        }
        if let alpnProtocols {
            extensions.extensionField(.alpn) { body in
                body.vector16 { list in
                    for name in alpnProtocols {
                        list.vector8 { $0.raw(name.utf8) }
                    }
                }
            }
        }
        if let recordSizeLimit {
            extensions.extensionField(.recordSizeLimit) { $0.u16(recordSizeLimit) }
        }
    }

    /// early_data / cookie / versions / shares / PSK modes.
    private func appendKeyExchangeExtensions(_ extensions: inout TLSHandshakeBuilder) {
        if offersEarlyData {
            extensions.extensionField(.earlyData) { _ in
                // §4.2.10: empty in a ClientHello
            }
        }
        if let cookie {
            extensions.extensionField(.cookie) { body in
                body.vector16 { $0.raw(cookie) }
            }
        }
        if let supportedVersions {
            extensions.extensionField(.supportedVersions) { body in
                body.vector8 { list in
                    for version in supportedVersions {
                        list.u16(version)
                    }
                }
            }
        }
        if let keyShares {
            extensions.extensionField(.keyShare) { body in
                body.vector16 { list in
                    for (group, key) in keyShares {
                        list.u16(group)
                        list.vector16 { $0.raw(key) }
                    }
                }
            }
        }
        if let pskKeyExchangeModes {
            extensions.extensionField(.pskKeyExchangeModes) { body in
                body.vector8 { $0.raw(pskKeyExchangeModes) }
            }
        }
    }

    /// The §4.2.11 offer, wherever the knobs place it.
    private func appendPreSharedKey(_ extensions: inout TLSHandshakeBuilder) {
        guard let preSharedKey else {
            return
        }
        extensions.extensionField(.preSharedKey) { body in
            body.vector16 { identities in
                for (ticket, age) in preSharedKey.identities {
                    identities.vector16 { $0.raw(ticket) }
                    identities.u32(age)
                }
            }
            body.vector16 { binders in
                for binder in preSharedKey.binders {
                    binders.vector8 { $0.raw(binder) }
                }
            }
        }
    }
}
