//
//  PortableTLSShutdownTests.swift
//  HTTPTransportTests
//
//  The bind contract's shutdown half, on the one backbone that accepts with a *blocking* `accept(2)`
//  thread: `shutdown()` must not return until the listening port is genuinely released, and it must
//  stay that way under concurrent and repeated calls.
//
//  This is where platform divergence hides. POSIX.1-2017 does not specify what `close(2)` does to a
//  thread blocked in `accept(2)` on the same descriptor, and the two kernels this package ships on
//  answer differently (measured, 2026-08): Darwin releases the bound port synchronously inside
//  `close(2)` and wakes the blocked accept with `ECONNABORTED`; Linux neither wakes the accept nor
//  releases the port — the socket stays bound until the accept's file reference drops, which is
//  *never* if no connection ever arrives. On Linux it is `shutdown(2)` `SHUT_RDWR` on the listening
//  socket that both releases the port (immediately, before the woken thread has even left the
//  syscall) and wakes the accept with `EINVAL`. A close-only `shutdown()` therefore passes every
//  macOS run and leaks the port on every Linux run — which is why these tests must run on both jobs.
//
//  A vacuous version of these tests exists and passes: stop the transport within microseconds of
//  starting it, and the accept thread loses the startup race — it observes `isRunning == false` and
//  exits without ever *entering* `accept(2)`, so a close-only shutdown releases the port and every
//  cycle rebinds. Measured on the Linux job: four cycles, four vacuous passes, against the very
//  semantics the probe above proves broken. So every cycle here first completes a real TLS handshake
//  through the transport — the handshake task only runs after the accept thread has surfaced the
//  connection and looped back into `accept(2)`, which is what puts the thread where the defect is.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — the opt-in portable build (`HTTP_PORTABLE_TLS`).
//
//  Standards: `bind(2)`/`listen(2)`/`accept(2)`/`close(2)`/`shutdown(2)` per POSIX.1-2017 (IEEE Std
//  1003.1-2017); `EADDRINUSE` (errno 48 Darwin, 98 Linux) is POSIX's answer while a listening socket
//  still holds the local address. TLS 1.3 RFC 8446 over TCP RFC 9293 over IPv4 RFC 791. CWE-404
//  (improper resource shutdown or release).
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    internal import CHTTPBoringSSLShims
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS — shutdown releases the port before it returns", .realNetwork)
    struct PortableTLSShutdownTests {
        @Test(
            "stop, then bind the same configured port again — four times in a row",
            .timeLimit(.minutes(1)))
        func rebindAfterStopReleasesThePort() async throws {
            let identity = try DevTLSIdentity.selfSigned()
            let port = try BindContractSubject.unusedPort(BindContractSubject.streamSocketType)
            for cycle in 0 ..< 4 {
                let transport = PortableTLSTransport(
                    configuration: TransportConfiguration(
                        host: "127.0.0.1",
                        port: port,
                        backbone: .portableTLS,
                        tls: identity
                    )
                )
                // On a `shutdown()` that returns with the port still held, this is the line that
                // fails on the next cycle: `bind(2)` answers EADDRINUSE for exactly as long as the
                // previous listener holds the address.
                let stream = try await transport.start()
                #expect(
                    transport.boundPort == port,
                    "cycle \(cycle) bound \(transport.boundPort), not \(port)"
                )
                let drain = Task {
                    for await _ in stream {
                        // Connections need no serving; the loop holds a consumer on the stream.
                    }
                }
                // Park the accept thread INSIDE `accept(2)` before stopping — see the file comment
                // for why the row is vacuous without this.
                #expect(Self.handshake(port: port), "cycle \(cycle): the TLS dial failed")
                // Mirror the matrix's stop shape: a consumer drops the stream (arming the
                // `onTermination` shutdown task) *and* calls `shutdown()` explicitly, so the two
                // race exactly as they do for every real consumer.
                drain.cancel()
                await transport.shutdown()
                withExtendedLifetime(stream) {
                    // Held until the listener is down.
                }
            }
        }

        @Test(
            "shutdown() is idempotent under concurrent and repeated calls, and still frees the port",
            .timeLimit(.minutes(1)))
        func shutdownIsIdempotentAndStillReleasesThePort() async throws {
            let identity = try DevTLSIdentity.selfSigned()
            let port = try BindContractSubject.unusedPort(BindContractSubject.streamSocketType)
            for cycle in 0 ..< 3 {
                let transport = PortableTLSTransport(
                    configuration: TransportConfiguration(
                        host: "127.0.0.1",
                        port: port,
                        backbone: .portableTLS,
                        tls: identity
                    )
                )
                let stream = try await transport.start()
                #expect(
                    transport.boundPort == port,
                    "cycle \(cycle) bound \(transport.boundPort), not \(port)"
                )
                let drain = Task {
                    for await _ in stream {
                        // Connections need no serving; the loop holds a consumer on the stream.
                    }
                }
                #expect(Self.handshake(port: port), "cycle \(cycle): the TLS dial failed")
                drain.cancel()
                // Four overlapping callers, then one strictly afterwards: the losers of the
                // take-the-descriptor race must wait for the winner's close, not return through the
                // `nil` they found — a joiner that returns early is exactly a rebind failure on the
                // next cycle.
                await withTaskGroup(of: Void.self) { group in
                    for _ in 0 ..< 4 {
                        group.addTask { await transport.shutdown() }
                    }
                }
                await transport.shutdown()
                withExtendedLifetime(stream) {
                    // Held until the listener is down.
                }
            }
        }

        // MARK: - Helpers

        /// Completes one TLS handshake against the loopback listener at `port`, then hangs up.
        ///
        /// Success proves the accept thread has accepted, surfaced the connection, and looped back
        /// into `accept(2)`: the handshake is driven by a task the accept thread spawns strictly
        /// before it re-enters the syscall. Blocking, but bounded — the descriptor carries a five
        /// second `SO_RCVTIMEO`/`SO_SNDTIMEO` (POSIX.1-2017), so a listener that never answers fails
        /// the cycle rather than parking a cooperative-pool thread for the suite's lifetime.
        private static func handshake(port: UInt16) -> Bool {
            let descriptor = CHTTPBoringSSLShims_connect_loopback(port)
            guard descriptor >= 0 else {
                return false
            }
            defer { _ = close(descriptor) }
            var deadline = timeval(tv_sec: 5, tv_usec: 0)
            let size = socklen_t(MemoryLayout<timeval>.size)
            _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &deadline, size)
            _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &deadline, size)
            guard let client = try? PortableTLSLoopback.makeClient(descriptor: descriptor) else {
                return false
            }
            defer {
                CHTTPBoringSSL_SSL_free(client.ssl)
                CHTTPBoringSSL_SSL_CTX_free(client.context)
            }
            return CHTTPBoringSSL_SSL_connect(client.ssl) == 1
        }
    }

#endif
