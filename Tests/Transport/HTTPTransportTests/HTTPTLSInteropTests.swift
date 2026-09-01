//
//  HTTPTLSInteropTests.swift
//  HTTPTransportTests
//
//  Phase 3d's decisive gate: REAL clients against the portable TLS backbone — the system
//  `curl` and `openssl s_client`, not this package's own primitives — covering the matrix
//  the phase is judged on: TLS 1.3 handshake, ALPN selection, echo round-trip, §4.6.1
//  session-ticket issuance, client-auth accept + reject, SNI multi-cert selection, hot
//  identity reload, and §4.6.3 KeyUpdate. Compiled under BOTH engine gates on purpose, so
//  the same matrix can be diffed engine-against-engine while the temporary A/B gate lives.
//
//  Every scenario prints one `INTEROP:` line — client, command, verdict — so a test log IS
//  the recorded matrix. Scenarios needing OpenSSL 3 semantics (`-msg` KeyUpdate echo, the
//  post-handshake ticket banner) resolve a real OpenSSL (Homebrew/apt) and are skipped —
//  visibly, via `.enabled(if:)` — where only LibreSSL exists.
//
//  Standards: TLS 1.3 (RFC 8446): §4.4.2.4 certificate_required, §4.6.1 NewSessionTicket,
//  §4.6.3 KeyUpdate; ALPN (RFC 7301); SNI (RFC 6066 §3).
//

#if canImport(CHTTPBoringSSLShims) || HTTP_PORTABLE_TLS_SWIFT

    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Foundation
    import HTTPTestSupport
    internal import Synchronization
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS — the real-client interop matrix (Phase 3d)", .realNetwork)
    struct HTTPTLSInteropTests {
        @Test(
            "curl: TLS 1.3 handshake, http/1.1 ALPN, HTTP round-trip",
            .enabled(if: InteropTools.curl != nil),
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func curlRoundTrip() async throws {
            var tls = try PortableTLSLoopback.devTLS()
            tls.applicationProtocols = ["http/1.1"]
            let server = try await InteropServer(tls: tls)
            defer { server.tearDown() }
            let curl = try #require(InteropTools.curl)
            let arguments = [
                "-sk", "--tlsv1.3", "--http1.1", "-w", "\\n%{http_version}",
                "https://127.0.0.1:\(server.port)/"
            ]
            let output = try InteropTools.run(curl, arguments, timeout: 30)
            let verdict = output.contains("portable-interop-ok") && output.contains("1.1")
            InteropTools.record("curl", arguments, pass: verdict, detail: output)
            #expect(verdict)
            #expect(await server.sawNegotiatedProtocol("http/1.1"))
        }

        @Test(
            "openssl s_client: TLS 1.3, h2 selected from the h2+http/1.1 ALPN offer",
            .enabled(if: InteropTools.openssl != nil),
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func alpnSelectsH2() async throws {
            let server = try await InteropServer(tls: try PortableTLSLoopback.devTLS())
            defer { server.tearDown() }
            let openssl = try #require(InteropTools.openssl)
            let arguments = [
                "s_client", "-connect", "127.0.0.1:\(server.port)", "-tls1_3",
                "-alpn", "h2,http/1.1"
            ]
            let output = try InteropTools.run(openssl, arguments, stdin: "", timeout: 30)
            let verdict =
                output.contains("ALPN protocol: h2") && output.contains("TLSv1.3")
            InteropTools.record("openssl", arguments, pass: verdict, detail: output)
            #expect(verdict)
        }

        @Test(
            "openssl s_client: echo round-trip and session-ticket issuance",
            .enabled(if: InteropTools.opensslThree != nil),
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func echoAndSessionTickets() async throws {
            let server = try await InteropServer(tls: try PortableTLSLoopback.devTLS())
            defer { server.tearDown() }
            let openssl = try #require(InteropTools.opensslThree)
            let arguments = [
                "s_client", "-connect", "127.0.0.1:\(server.port)", "-tls1_3"
            ]
            let client = try InteropClient(openssl, arguments)
            defer { client.terminate() }
            client.send("interop-echo-probe\n")
            let echoed = client.awaitOutput(containing: "srv:interop-echo-probe", seconds: 15)
            let ticketed = client.awaitOutput(
                containing: "Post-Handshake New Session Ticket", seconds: 15
            )
            InteropTools.record(
                "openssl",
                arguments + ["<<< echo probe"],
                pass: echoed && ticketed,
                detail: client.transcript()
            )
            #expect(echoed, "the echo must cross the session both ways")
            #expect(ticketed, "handshake completion must issue NewSessionTickets (§4.6.1)")
        }

        @Test(
            "openssl s_client: KeyUpdate (K) is honored and answered",
            .enabled(if: InteropTools.opensslThree != nil),
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func keyUpdateIsAnswered() async throws {
            let server = try await InteropServer(tls: try PortableTLSLoopback.devTLS())
            defer { server.tearDown() }
            let openssl = try #require(InteropTools.opensslThree)
            // `-msg` prints every handshake message BOTH directions, which is what proves
            // our ANSWER (§4.6.3: an update_requested must be answered with our own
            // KeyUpdate); the post-update echo proves both sides ratcheted correctly.
            let arguments = [
                "s_client", "-connect", "127.0.0.1:\(server.port)", "-tls1_3", "-msg"
            ]
            let client = try InteropClient(openssl, arguments)
            defer { client.terminate() }
            _ = client.awaitOutput(containing: "NewSessionTicket", seconds: 15)
            client.send("K\n")  // s_client: request a mutual KeyUpdate
            client.send("post-keyupdate-probe\n")
            let echoed = client.awaitOutput(
                containing: "srv:post-keyupdate-probe", seconds: 15
            )
            let answered = client.transcript().components(separatedBy: "KeyUpdate").count > 2
            InteropTools.record(
                "openssl",
                arguments + ["<<< K, then echo probe"],
                pass: echoed && answered,
                detail: client.transcript()
            )
            #expect(echoed, "data must flow under the ratcheted keys (§4.6.3/§7.2)")
            #expect(answered, "the update_requested KeyUpdate must be answered (§4.6.3)")
        }

        @Test(
            "openssl s_client: required client auth accepts a certificate and rejects none",
            .enabled(if: InteropTools.openssl != nil),
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func mutualTLSAcceptAndReject() async throws {
            var tls = try PortableTLSLoopback.devTLS()
            tls.clientAuth = .required
            tls.verifyPeer = { chain in !chain.isEmpty }
            let server = try await InteropServer(tls: tls)
            defer { server.tearDown() }
            let openssl = try #require(InteropTools.openssl)
            let identity = try DevTLSIdentity.selfSignedPEM(commonName: "interop-client")
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("interop-mtls-\(UInt32.random(in: 0 ... .max))")
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: directory) }
            let certificate = directory.appendingPathComponent("client.pem").path
            let key = directory.appendingPathComponent("client.key").path
            try identity.certificatePEM.write(
                toFile: certificate, atomically: true, encoding: .utf8
            )
            try identity.privateKeyPEM.write(toFile: key, atomically: true, encoding: .utf8)

            let accepted = [
                "s_client", "-connect", "127.0.0.1:\(server.port)", "-tls1_3",
                "-cert", certificate, "-key", key
            ]
            let acceptOutput = try InteropTools.run(openssl, accepted, stdin: "", timeout: 30)
            let acceptVerdict = acceptOutput.contains("TLSv1.3")
            InteropTools.record("openssl", accepted, pass: acceptVerdict, detail: acceptOutput)
            #expect(acceptVerdict)
            #expect(await server.sawPeerSubject("interop-client"))

            let surfacedBeforeReject = server.surfacedConnections()
            let rejected = [
                "s_client", "-connect", "127.0.0.1:\(server.port)", "-tls1_3"
            ]
            // The probe forces the client to READ after its flight, so the §4.4.2.4
            // certificate_required alert reaches its transcript where the tool names it.
            let rejectOutput = try InteropTools.run(
                openssl, rejected, stdin: "probe\n", timeout: 30
            )
            try await Task.sleep(for: .seconds(1))  // let a (wrongly) accepted surface land
            // The decisive oracle is SERVER-side: a refused handshake must never surface.
            // The transcript check is corroboration — alert spellings differ per client.
            let neverSurfaced = server.surfacedConnections() == surfacedBeforeReject
            let alerted =
                rejectOutput.contains("certificate required")
                || rejectOutput.contains("alert number 116")
                || rejectOutput.contains("handshake failure")
            InteropTools.record(
                "openssl",
                rejected,
                pass: neverSurfaced,
                detail: "alert seen: \(alerted)\n" + rejectOutput
            )
            #expect(neverSurfaced, "a certificate-less client must never be surfaced")
        }

        @Test(
            "openssl s_client: SNI selects the per-name certificate, else the default",
            .enabled(if: InteropTools.openssl != nil),
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 2)))
        func sniSelectsCertificate() async throws {
            var tls = try PortableTLSLoopback.devTLS()  // default CN=localhost
            tls.sniIdentities = [
                "alpha.test": try PortableTLSLoopback.devSNIIdentity(commonName: "alpha.test")
            ]
            let server = try await InteropServer(tls: tls)
            defer { server.tearDown() }
            let openssl = try #require(InteropTools.openssl)
            for (name, expected) in [("alpha.test", "alpha.test"), ("other.test", "localhost")] {
                let arguments = [
                    "s_client", "-connect", "127.0.0.1:\(server.port)", "-tls1_3",
                    "-servername", name
                ]
                let output = try InteropTools.run(openssl, arguments, stdin: "", timeout: 30)
                let verdict = InteropTools.subjectLine(of: output).contains(expected)
                InteropTools.record("openssl", arguments, pass: verdict, detail: output)
                #expect(verdict, "server_name \(name) must be served CN \(expected)")
            }
        }

        @Test(
            "openssl s_client: a hot reload serves the new identity to new handshakes",
            .enabled(if: InteropTools.openssl != nil),
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 2)))
        func hotReloadServesNewIdentity() async throws {
            let server = try await InteropServer(
                tls: try PortableTLSLoopback.devTLS(commonName: "interop-before")
            )
            defer { server.tearDown() }
            let openssl = try #require(InteropTools.openssl)
            let arguments = [
                "s_client", "-connect", "127.0.0.1:\(server.port)", "-tls1_3"
            ]
            let before = try InteropTools.run(openssl, arguments, stdin: "", timeout: 30)
            let beforeVerdict = InteropTools.subjectLine(of: before).contains("interop-before")
            InteropTools.record("openssl", arguments, pass: beforeVerdict, detail: before)
            #expect(beforeVerdict)

            try await server.reload(
                tls: try PortableTLSLoopback.devTLS(commonName: "interop-after")
            )
            let after = try InteropTools.run(openssl, arguments, stdin: "", timeout: 30)
            let afterVerdict = InteropTools.subjectLine(of: after).contains("interop-after")
            InteropTools.record(
                "openssl",
                arguments + ["(after reload)"],
                pass: afterVerdict,
                detail: after
            )
            #expect(afterVerdict, "a fresh handshake after reload must see the new identity")
        }
    }

#endif
