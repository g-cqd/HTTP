//
//  PortableTLSSendFileOwnershipTests.swift
//  HTTPTransportTests
//
//  Audit F-03, outbound half: who owns the send direction for the DURATION of a file body.
//
//  ``PortableTLSConnection`` carried no `sendFile` override, so it inherited the copying default,
//  whose `try await send(...)` sits INSIDE the chunk loop. Its ``PortableTLSConnection/send(_:)`` is
//  gated by the outbound exclusion, so the inherited shape took and released the lease once per
//  64 KiB chunk — and between two chunks the direction is free, which is the whole point of a lease.
//  A sender that arrives in that window is admitted, and its octets land in the MIDDLE of a body the
//  peer is reading against a `Content-Length` it was already given (RFC 9112 §6.2). That is silent
//  corruption of one response by another, not a transport error the peer can see.
//
//  Forced, not hoped for. The socket pair's send window is a couple of KiB and the peer does not read
//  until the test says so, so the first chunk's drain is CERTAIN to park with the exclusion held; the
//  interposing sender then queues behind it, and ``PortableTLSConnection/awaitQueuedSenders(atLeast:)``
//  returns exactly at that contended moment. Nothing here polls for an interleaving it hopes to see:
//  the state is established before a single byte is asserted on. Verified by mutation — deleting the
//  override and letting the inherited default run again fails this on every run, with the marker
//  sitting at octet 65,536 of a 200,000-octet body.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — the opt-in portable build (`HTTP_PORTABLE_TLS`).
//
//  Standards: TLS 1.3 (RFC 8446) — §5.1 record ordering over a reliable transport; the splice here is
//  *plaintext* rather than ciphertext, so the peer's TLS layer accepts it and the damage surfaces one
//  layer up, in the HTTP/1.1 message framing of RFC 9112 §6.2. `pread()`/`socketpair()` per
//  POSIX.1-2017 (IEEE Std 1003.1-2017). CWE-362 (concurrent execution using a shared resource without
//  proper synchronization).
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
    internal import Foundation
    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    @Suite(
        "Portable TLS — sendFile owns the direction for the whole body (audit F-03)",
        .realNetwork)
    struct PortableTLSSendFileOwnershipTests {
        /// Comfortably more than three inherited-default chunks, so a per-chunk lease is released
        /// three times mid-body rather than once at a boundary that could be argued away.
        private static let bodyOctets = 200_000

        /// The interposing sender's payload — one response's worth of header-ish octets, sized to be
        /// found instantly in a diff rather than to stress anything.
        private static let marker = Array("HTTP/1.1 500 INTERPOSED\r\n\r\n".utf8)

        @Test(
            "a concurrent sender cannot splice its octets into a file body",
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func aQueuedSenderCannotSpliceIntoAFileBody() async throws {
            let body = Self.bodyPattern()
            let harness = try Harness(body: body)
            defer { harness.tearDown() }
            harness.startPeer(expecting: body.count + Self.marker.count)
            try await harness.connection.performHandshake()

            let connection = harness.connection
            let descriptor = harness.bodyDescriptor
            let sender = Task {
                try await connection.sendFile(
                    descriptor: descriptor,
                    offset: 0,
                    length: body.count
                )
            }
            // Wait for the file send to OWN the direction. The peer is not reading, so the first
            // chunk's drain parks with the exclusion held and cannot hand it back until this test
            // releases the peer — the observation is of a state that is stable, not of a moment.
            while !connection.isSendPumpHeld {
                await Task.yield()
            }
            let interposer = Task { try await connection.send(Self.marker) }
            // Deterministic: exactly one sender is queued behind the file send now.
            try await connection.awaitQueuedSenders(atLeast: 1)

            harness.releasePeer()
            try await sender.value
            try await interposer.value
            let delivered = try await harness.delivered.wait(forAtLeast: 1)
            let plaintext = try #require(delivered.first)

            #expect(
                plaintext == body + Self.marker,
                Self.spliceReport(plaintext, body: body)
            )
            #expect(!connection.isSendPumpHeld, "both sends must hand the direction back")
            await connection.close()
        }

        /// A file body sent with no contention still arrives byte-exact, and frees the direction.
        ///
        /// The control on the fix: an override that took the exclusion and never released it, or that
        /// mis-drove the ungated encrypt core, would pass the splice test above by hanging the second
        /// sender forever. This one has no second sender to hide behind.
        @Test(
            "an uncontended file body arrives byte-exact and frees the direction",
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func anUncontendedFileBodyArrivesIntact() async throws {
            let body = Self.bodyPattern()
            let harness = try Harness(body: body)
            defer { harness.tearDown() }
            harness.startPeer(expecting: body.count - 128)
            try await harness.connection.performHandshake()

            harness.releasePeer()
            // A sub-range proves the offset plumbing rather than just whole-file delivery.
            try await harness.connection.sendFile(
                descriptor: harness.bodyDescriptor,
                offset: 128,
                length: body.count - 128
            )
            let delivered = try await harness.delivered.wait(forAtLeast: 1)
            #expect(delivered.first == Array(body[128...]))
            #expect(!harness.connection.isSendPumpHeld)
            #expect(!harness.connection.isReceivePumpHeld)
            await harness.connection.close()
        }

        /// A file that ends short of the framed length fails rather than truncating the body.
        ///
        /// The inherited default fails closed here (a short body desyncs the connection); the override
        /// has to keep doing so, and has to hand the direction back while doing it.
        @Test(
            "a file shorter than the framed length fails and still frees the direction",
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)))
        func aShortFileFailsClosedAndFreesTheDirection() async throws {
            let body = Self.bodyPattern()
            let harness = try Harness(body: body)
            defer { harness.tearDown() }
            harness.startPeer(expecting: body.count)
            try await harness.connection.performHandshake()
            harness.releasePeer()

            await #expect(throws: TransportError.self) {
                try await harness.connection.sendFile(
                    descriptor: harness.bodyDescriptor,
                    offset: 0,
                    length: body.count + 4_096
                )
            }
            #expect(
                !harness.connection.isSendPumpHeld,
                "a failed file send must hand the direction back, not strand it"
            )
            await harness.connection.close()
        }

        // MARK: - Oracles

        /// Every octet value, in a pattern that makes any displacement visible at any offset.
        private static func bodyPattern() -> [UInt8] {
            (0 ..< bodyOctets).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ ($0 >> 8)) }
        }

        /// Where the delivered stream first stops matching the file body — the splice offset.
        ///
        /// A bare "not equal" on 200,000 octets says nothing about WHICH failure happened; this names
        /// the chunk boundary the lease was released at, which is the whole claim.
        private static func spliceReport(_ delivered: [UInt8], body: [UInt8]) -> Comment {
            let shared = min(delivered.count, body.count)
            var index = 0
            while index < shared, delivered[index] == body[index] {
                index += 1
            }
            guard index < shared else {
                return "the file body was truncated at \(delivered.count) of \(body.count) octets"
            }
            return """
                the file body was spliced at octet \(index) of \(body.count) — a concurrent send \
                landed inside it, so the outbound lease was released mid-body
                """
        }

        // MARK: - Harness

        /// A handshaken server connection over a narrow socket pair, a raw libssl peer that reads only
        /// when released, and a temporary file holding the body under test.
        private final class Harness {
            let connection: PortableTLSConnection
            let bodyDescriptor: Int32
            let delivered = AsyncEventProbe<[UInt8]>()

            private let loop: TLSEventLoop
            private let serverContext: OpaquePointer
            private let clientDescriptor: Int32
            private let peer: (ssl: OpaquePointer, context: OpaquePointer)
            private let bodyURL: URL
            /// Held closed until the test has established the contended state it asserts on.
            private let release = DispatchSemaphore(value: 0)
            /// Joins the background peer before ``tearDown()`` frees the `SSL` it is still using.
            private let finished = DispatchSemaphore(value: 0)
            private var startedPeer = false

            init(body: [UInt8]) throws {
                let identity = try DevTLSIdentity.selfSigned()
                serverContext = try OpenSSLTLS.serverContext(identity)
                let pair = PortableTLSLoopback.makeSocketPair()
                clientDescriptor = pair.client
                loop = try TLSEventLoop()
                loop.start()
                connection = try PortableTLSLoopback.makeConnection(
                    serverContext,
                    descriptor: pair.server,
                    loop: loop
                )
                peer = try PortableTLSLoopback.makeClient(descriptor: pair.client)
                let name = "portable-tls-sendfile-\(UInt32.random(in: 0 ... .max))"
                bodyURL = FileManager.default.temporaryDirectory.appendingPathComponent(name)
                try Data(body).write(to: bodyURL)
                bodyDescriptor = open(bodyURL.path, O_RDONLY)
                #expect(bodyDescriptor >= 0)
            }

            deinit {
                // Every handle is released in `tearDown()`, which each test runs from a `defer` once
                // the background peer closure is known to have finished. Doing it here instead would
                // free the `SSL` on whichever thread dropped the last reference, possibly out from
                // under that closure.
            }

            /// Handshakes on a background thread, then stays silent AND unread until ``releasePeer()``.
            ///
            /// The silence is the forcing function: with a couple of KiB of socket window and nobody
            /// draining it, the server's first chunk cannot complete, so the exclusion it took is still
            /// held when the test looks.
            func startPeer(expecting octets: Int) {
                startedPeer = true
                // `SSL` access is confined to this one background closure, which is what makes the
                // non-Sendable `OpaquePointer` safe to hand it — `nonisolated(unsafe)` states that.
                nonisolated(unsafe) let ssl = peer.ssl
                let gate = release
                let done = finished
                let sink = delivered
                DispatchQueue.global(qos: .userInitiated)
                    .async {
                        defer { done.signal() }
                        guard CHTTPBoringSSL_SSL_connect(ssl) == 1 else {
                            return sink.record([])
                        }
                        gate.wait()
                        sink.record(PortableTLSLoopback.drain(ssl, upTo: octets))
                    }
            }

            /// Lets the peer start draining — the only thing that can end the server's parked write.
            func releasePeer() {
                release.signal()
            }

            /// Joins the background peer, then frees every handle in dependency order.
            func tearDown() {
                // Harmless for a peer already draining; unblocks one still waiting to be released.
                release.signal()
                if startedPeer {
                    // A bound, not a measurement: the peer either finished long ago or the
                    // connection is already torn down under it.
                    _ = finished.wait(timeout: .now() + .seconds(20))
                }
                if bodyDescriptor >= 0 {
                    _ = close(bodyDescriptor)
                }
                try? FileManager.default.removeItem(at: bodyURL)
                CHTTPBoringSSL_SSL_free(peer.ssl)
                CHTTPBoringSSL_SSL_CTX_free(peer.context)
                _ = close(clientDescriptor)
                CHTTPBoringSSL_SSL_CTX_free(serverContext)
                loop.stop()
            }
        }
    }

#endif
