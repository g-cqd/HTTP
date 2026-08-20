//
//  HTTPTLSEngineParityTests.swift
//  HTTPTransportTests
//
//  Phase 3d — the HTTPTLS engine's twins of the claims whose LEGACY tests moved behind
//  `HTTP_BORINGSSL_TLS` (they assert BoringSSL mechanics: error-queue draining, `SSL_CTX`
//  plumbing, the `ReceiveScratch` plaintext floor of the libssl pump). The CLAIMS survive
//  the engine; their new spellings live here:
//
//  - Intake fails closed (the `OpenSSLTLS.serverContext` rejection tests' twin): PKCS#12
//    identities, a 1.3-excluding version ceiling, and undecodable PEM die at context
//    construction with a typed error — never at the first handshake.
//  - Failure evidence keeps the field-report grep prefix (`SSL_accept error 1 [connection`)
//    while carrying the typed alert + reason instead of a drained error queue.
//  - Residency: a constructed connection holds NO pump buffers, and an ordinary request
//    leaves less resident than the legacy engine's plaintext floor — the ADD-P2 claim,
//    strictly tightened.
//
//  Gated `#if HTTP_PORTABLE_TLS_SWIFT` — the HTTPTLS-engined portable build only.
//

#if HTTP_PORTABLE_TLS_SWIFT

    internal import CHTTPBoringSSL
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Dispatch
    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS (HTTPTLS engine) — intake, evidence, residency twins", .realNetwork)
    struct HTTPTLSEngineParityTests {
        @Test("a PKCS#12-only default identity fails closed at intake, naming the way out")
        func pkcs12DefaultIdentityFailsClosed() throws {
            let tls = TransportTLS(pkcs12: [0x30, 0x82], passphrase: "irrelevant")
            #expect {
                _ = try PortableTLSServerContext(tls)
            } throws: { error in
                guard case TransportError.tlsConfigurationFailed(let message) = error else {
                    return false
                }
                return message.contains("PKCS#12") && message.contains("openssl pkcs12 -nodes")
            }
        }

        @Test("a PKCS#12-only SNI entry fails closed at intake, naming the entry")
        func pkcs12SNIIdentityFailsClosed() throws {
            var tls = try PortableTLSLoopback.devTLS()
            tls.sniIdentities = [
                "legacy.test": TransportTLS.SNIIdentity(pkcs12: [0x30], passphrase: "")
            ]
            #expect {
                _ = try PortableTLSServerContext(tls)
            } throws: { error in
                guard case TransportError.tlsConfigurationFailed(let message) = error else {
                    return false
                }
                return message.contains("legacy.test") && message.contains("PKCS#12")
            }
        }

        @Test("a TLS 1.2 ceiling fails closed at intake — the engine is 1.3-only")
        func tls12CeilingFailsClosed() throws {
            var tls = try PortableTLSLoopback.devTLS()
            tls.maxVersion = .tlsV12
            #expect {
                _ = try PortableTLSServerContext(tls)
            } throws: { error in
                guard case TransportError.tlsConfigurationFailed(let message) = error else {
                    return false
                }
                return message.contains("TLS 1.3-only")
            }
        }

        @Test("undecodable PEM fails closed at intake with the load-time defect named")
        func malformedPEMFailsClosed() throws {
            let tls = TransportTLS(
                pem: TransportTLS.PEMIdentity(
                    certificateChainPEM: "not a certificate",
                    privateKeyPEM: "not a key"
                )
            )
            #expect {
                _ = try PortableTLSServerContext(tls)
            } throws: { error in
                guard case TransportError.tlsConfigurationFailed(let message) = error else {
                    return false
                }
                return message.contains("PEM identity rejected")
            }
        }

        @Test("failure evidence keeps the field-report prefix and carries alert + reason")
        func evidenceKeepsTheGrepPrefix() throws {
            let context = try PortableTLSServerContext(try PortableTLSLoopback.devTLS())
            defer { context.release() }
            guard var engine = context.makeEngine(connectionID: TransportConnectionID(41))
            else {
                Issue.record("the context minted no engine")
                return
            }
            let pair = PortableTLSLoopback.makeSocketPair()
            defer {
                _ = close(pair.server)
                _ = close(pair.client)
            }
            // A cleartext HTTP request where a ClientHello belongs — the classic mis-dial.
            // Its first octet is no TLS content type, so the record layer refuses it.
            let misdial = Array("GET / HTTP/1.1\r\nHost: oops\r\n\r\n".utf8)
            #expect(
                misdial.withUnsafeBytes { write(pair.client, $0.baseAddress, $0.count) }
                    == misdial.count
            )
            #expect(try engine.ingestCiphertext(from: pair.server))
            guard case .failed(let evidence) = engine.acceptHandshake() else {
                Issue.record("a cleartext feed must classify as fatal")
                return
            }
            // The historical prefix, byte-for-byte (`SSL_ERROR_SSL` is 1), then the typed
            // capture the old report lacked.
            #expect(evidence.description.hasPrefix("SSL_accept error 1 [connection 41 "))
            #expect(evidence.description.contains("alert"))
            #expect(evidence.description.contains("reason"))
            // Poisoned forever, like an errored `SSL`: the next call repeats the evidence.
            guard case .failed = engine.acceptHandshake() else {
                Issue.record("a failed engine must stay failed")
                return
            }
        }

        @Test(
            "an ordinary request leaves less resident than the legacy plaintext floor",
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func ordinaryRequestResidencyIsBounded() async throws {
            let context = try PortableTLSServerContext(try PortableTLSLoopback.devTLS())
            defer { context.release() }
            let pair = PortableTLSLoopback.makeSocketPair()
            let loop = try TLSEventLoop()
            loop.start()
            defer { loop.stop() }
            let connection = try PortableTLSLoopback.makeConnection(
                context, descriptor: pair.server, loop: loop
            )
            #expect(
                connection.ciphertextScratchBytes == 0,
                "a constructed connection must hold no pump buffer at all"
            )
            #expect(connection.receiveScratchBytes == 0)

            let client = try PortableTLSLoopback.makeClient(descriptor: pair.client)
            let head = Array("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".utf8)
            let finished = AsyncEventProbe<Void>()
            nonisolated(unsafe) let clientSSL = client.ssl
            DispatchQueue.global()
                .async {
                    defer { finished.record(()) }
                    guard CHTTPBoringSSL_SSL_connect(clientSSL) == 1 else {
                        return
                    }
                    _ = head.withUnsafeBytes {
                        CHTTPBoringSSL_SSL_write(clientSSL, $0.baseAddress, Int32($0.count))
                    }
                }
            try await connection.performHandshake()
            var buffer: [UInt8] = []
            while buffer.count < head.count {
                let count = try await connection.receive(into: &buffer, maxLength: 16_384)
                guard count > 0 else {
                    break
                }
            }
            #expect(buffer == head)
            // Stronger than the legacy claim: this engine's plaintext buffer is sized by the
            // records that actually arrived (~40 octets here), not by a 2 KiB scratch floor.
            #expect(connection.receiveScratchBytes < ReceiveScratch.floorWindow)
            // The pump side stays bounded well under one max record either way.
            #expect(connection.ciphertextScratchBytes < 16_384)
            await connection.close()
            _ = try await finished.wait(forAtLeast: 1)
            CHTTPBoringSSL_SSL_free(client.ssl)
            CHTTPBoringSSL_SSL_CTX_free(client.context)
            _ = close(pair.client)
        }
    }

#endif
