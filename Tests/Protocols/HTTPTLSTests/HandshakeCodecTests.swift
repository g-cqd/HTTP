//
//  HandshakeCodecTests.swift
//  HTTPTLSTests
//
//  The §4 codec against the RFC 8448 fixtures: the ClientHello parser must recover every
//  field of the traces' hellos (including the §4.2.11.2 truncation offset, cross-checked
//  against the trace's published binder-prefix length), and the coalescer must reassemble
//  messages across §5.1's fragmentation shapes — spanning records, sharing records, and
//  arriving one octet at a time.
//

import Testing

@testable internal import HTTPTLS

@Suite("The §4 handshake codec against the RFC 8448 fixtures")
struct HandshakeCodecTests {
    /// Reassembles one message from raw bytes.
    private static func parseHello(_ raw: [UInt8]) throws -> TLSClientHello {
        var coalescer = TLSHandshakeCoalescer(maximumMessageLength: 1 << 17)
        coalescer.feed(raw)
        guard let message = try coalescer.next() else {
            throw TLSHandshakeError.internalError("incomplete fixture")
        }
        return try TLSClientHello.parse(message)
    }

    @Test("the §3 ClientHello parses field-for-field")
    func parseSimpleTraceHello() throws {
        let hello = try Self.parseHello(RFC8448Simple.clientHello)
        #expect(hello.legacyVersion == 0x0303)
        #expect(hello.serverName == "server")
        #expect(hello.cipherSuites == [0x1301, 0x1303, 0x1302])
        #expect(hello.compressionMethods == [0])
        #expect(hello.supportedVersions == [0x0304])
        #expect(hello.supportedGroups?.first == .x25519)
        #expect(hello.supportedGroups?.count == 9)
        #expect(hello.keyShares?.count == 1)
        #expect(hello.keyShares?.first?.group == .x25519)
        #expect(hello.keyShares?.first?.keyExchange.count == 32)
        #expect(hello.signatureAlgorithms?.contains(.rsaPssRsaeSha256) == true)
        #expect(hello.pskKeyExchangeModes == [1])
        #expect(hello.recordSizeLimit == 16_385)
        #expect(hello.preSharedKey == nil)
        #expect(!hello.offeredEarlyData)
    }

    @Test("the §4 ClientHello parses its PSK offer with the trace's exact truncation offset")
    func parseResumedTraceHello() throws {
        let hello = try Self.parseHello(RFC8448Resumed.clientHello)
        #expect(hello.offeredEarlyData)
        guard let offer = hello.preSharedKey else {
            Issue.record("expected a pre_shared_key offer")
            return
        }
        #expect(offer.identities.count == 1)
        #expect(offer.binders == [RFC8448Resumed.binderValue])
        // §4.2.11.2's Truncate(ClientHello) — the trace publishes the truncated prefix.
        #expect(offer.truncatedMessageLength == RFC8448Resumed.clientHelloBinderPrefix.count)
        #expect(
            [UInt8](RFC8448Resumed.clientHello[..<offer.truncatedMessageLength])
                == RFC8448Resumed.clientHelloBinderPrefix
        )
    }

    @Test("the §5 retried ClientHello parses cookie and P-256 share")
    func parseRetriedTraceHello() throws {
        let hello = try Self.parseHello(RFC8448HelloRetry.clientHello2)
        #expect(hello.cookie?.count == 114)
        #expect(hello.keyShares?.first?.group == .secp256r1)
        #expect(hello.keyShares?.first?.keyExchange.count == 65)
    }

    @Test("messages reassemble across §5.1 fragmentation shapes", arguments: [1, 3, 64, 4_096])
    func coalescerFragmentation(chunk: Int) throws {
        // Two messages back to back, delivered in `chunk`-sized fragments.
        let first = RFC8448Simple.clientHello
        let second = RFC8448Simple.serverHello
        let stream = first + second
        var coalescer = TLSHandshakeCoalescer(maximumMessageLength: 1 << 17)
        var messages: [[UInt8]] = []
        var cursor = 0
        while cursor < stream.count {
            let end = min(cursor + chunk, stream.count)
            coalescer.feed([UInt8](stream[cursor ..< end]))
            while let message = try coalescer.next() {
                messages.append(message.raw)
            }
            cursor = end
        }
        #expect(messages == [first, second])
        #expect(!coalescer.hasPartialMessage)
    }

    @Test("the coalescer caps declared lengths before buffering")
    func coalescerCap() {
        var coalescer = TLSHandshakeCoalescer(maximumMessageLength: 1_024)
        coalescer.feed([1, 0xFF, 0xFF, 0xFF])  // ClientHello claiming 2^24-1 octets
        #expect(throws: TLSHandshakeError.messageTooLarge(declared: 0xFF_FFFF, limit: 1_024)) {
            _ = try coalescer.next()
        }
    }

    @Test("the SPKI locator finds the RFC 8448 certificate's RSA public key")
    func spkiLocatorOnTraceCertificate() throws {
        let flight = try RFC8448Flight(RFC8448Simple.serverFlight)
        let spki = try DERPublicKeyLocator.subjectPublicKeyInfo(
            inCertificateDER: flight.certificateDER
        )
        // rsaEncryption OID 1.2.840.113549.1.1.1 must sit inside the located SPKI.
        let rsaOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        #expect(spki.count > rsaOID.count)
        #expect(
            (0 ... (spki.count - rsaOID.count))
                .contains { offset in
                    [UInt8](spki[offset ..< offset + rsaOID.count]) == rsaOID
                }
        )
    }
}
