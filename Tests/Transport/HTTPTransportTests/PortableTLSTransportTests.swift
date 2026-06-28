//
//  PortableTLSTransportTests.swift
//  HTTPTransportTests
//
//  Phase 3 of the portable TLS backbone (ADR 0004): the full `PortableTLSTransport` over real loopback
//  — bind, accept, handshake, surface at `.ready`. Two proofs: a libssl client negotiates ALPN `h2`
//  and round-trips bytes through the transport (deterministic, in-process), and **`curl` interops**
//  over TLS (a real non-Network.framework client — the portability proof), exchanging an HTTP/1.1
//  request/response and negotiating `http/1.1` ALPN. The `curl` test skips cleanly if `curl` is absent.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — runs only in the opt-in portable build (`HTTP_PORTABLE_TLS`).
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Dispatch
    import Foundation
    import HTTPTestSupport
    internal import Synchronization
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS (vendored BoringSSL) — Phase 3 transport (ADR 0004)")
    struct PortableTLSTransportTests {
        @Test(
            "the transport accepts a libssl client, negotiates ALPN h2, and round-trips bytes",
            .timeLimit(.minutes(1)))
        func transportAcceptsHandshakesAndEchoes() async throws {
            let transport = try Self.startedTransport()
            let connections = try await transport.start()
            let port = transport.boundPort
            #expect(port != 0)

            let serverALPN = Mutex<String?>(nil)
            let server = Task { () -> Bool in
                var iterator = connections.makeAsyncIterator()
                guard let connection = await iterator.next() else {
                    return false
                }
                serverALPN.withLock { $0 = connection.negotiatedApplicationProtocol }
                let received = try? await connection.receive(maxLength: 64)
                if let received {
                    try? await connection.send(received)
                }
                await connection.close()
                return received == [UInt8]("ping".utf8)
            }

            let echoed = AsyncEventProbe<[UInt8]>()
            DispatchQueue.global()
                .async {
                    let descriptor = CHTTPBoringSSLShims_connect_loopback(port)
                    guard descriptor >= 0,
                        let context = CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method())
                    else {
                        return
                    }
                    defer { CHTTPBoringSSL_SSL_CTX_free(context) }
                    CHTTPBoringSSL_SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
                    _ = CHTTPBoringSSLShims_set_client_alpn(context)
                    guard let ssl = CHTTPBoringSSL_SSL_new(context) else {
                        _ = close(descriptor)
                        return
                    }
                    defer {
                        CHTTPBoringSSL_SSL_free(ssl)
                        _ = close(descriptor)
                    }
                    CHTTPBoringSSL_SSL_set_fd(ssl, descriptor)
                    guard CHTTPBoringSSL_SSL_connect(ssl) == 1 else {
                        return
                    }
                    let ping = [UInt8]("ping".utf8)
                    _ = ping.withUnsafeBytes {
                        CHTTPBoringSSL_SSL_write(ssl, $0.baseAddress, Int32($0.count))
                    }
                    var buffer = [UInt8](repeating: 0, count: 64)
                    let count = buffer.withUnsafeMutableBytes {
                        CHTTPBoringSSL_SSL_read(ssl, $0.baseAddress, Int32($0.count))
                    }
                    if count > 0 {
                        buffer.removeLast(buffer.count - Int(count))
                        echoed.record(buffer)
                    }
                }

            let echoes = try await echoed.wait(forAtLeast: 1, timeout: .seconds(15))
            #expect(echoes.first == [UInt8]("ping".utf8))
            #expect(await server.value)
            #expect(serverALPN.withLock(\.self) == "h2")
            await transport.shutdown()
        }

        @Test(
            "curl interops over TLS through the transport (a real non-Network client)",
            .timeLimit(.minutes(1)))
        func curlInterop() async throws {
            guard let curl = Self.which("curl") else {
                return  // no curl on this host — skip the interop proof
            }
            let transport = try Self.startedTransport()
            let connections = try await transport.start()
            let port = transport.boundPort
            #expect(port != 0)

            let serverALPN = Mutex<String?>(nil)
            let server = Task {
                var iterator = connections.makeAsyncIterator()
                guard let connection = await iterator.next() else {
                    return
                }
                serverALPN.withLock { $0 = connection.negotiatedApplicationProtocol }
                _ = try? await connection.receive(maxLength: 4_096)  // curl's HTTP request
                let response =
                    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong"
                try? await connection.send([UInt8](response.utf8))
                await connection.close()
            }
            defer {
                server.cancel()
                Task { await transport.shutdown() }
            }

            let output = try Self.run(curl, ["-sk", "--http1.1", "https://127.0.0.1:\(port)/"])
            #expect(output.contains("pong"))
            #expect(serverALPN.withLock(\.self) == "http/1.1")
            await transport.shutdown()
        }

        // MARK: - Helpers

        /// A `PortableTLSTransport` on an ephemeral port with a fresh dev identity (ALPN h2 / http1.1).
        private static func startedTransport() throws -> PortableTLSTransport {
            let identity = try DevTLSIdentity.selfSigned()
            let configuration = TransportConfiguration(
                port: 0, backbone: .portableTLS, tls: identity
            )
            return PortableTLSTransport(configuration: configuration)
        }

        /// The first executable named `tool` on the common paths, or `nil` if none is installed.
        private static func which(_ tool: String) -> String? {
            let candidates = [
                "/usr/bin/\(tool)", "/opt/homebrew/bin/\(tool)", "/usr/local/bin/\(tool)"
            ]
            return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
        }

        /// Runs `executable` with `arguments`, returning its standard output.
        private static func run(_ executable: String, _ arguments: [String]) throws -> String {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            let output = Pipe()
            process.standardOutput = output
            process.standardError = Pipe()
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(decoding: data, as: Unicode.UTF8.self)
        }
    }

#endif
