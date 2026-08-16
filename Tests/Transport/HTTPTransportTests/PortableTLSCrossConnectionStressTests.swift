//
//  PortableTLSCrossConnectionStressTests.swift
//  HTTPTransportTests
//
//  The sentinel for the one field failure this backbone never explained: a healthy session's
//  `SSL_read error 1` carrying `PEER_DID_NOT_RETURN_A_CERTIFICATE` — an entry only ever pushed by a
//  server that requires client auth and receives none (`tls13_both.cc:302`) — observed roughly one
//  run in twelve while the mutual-TLS `.required` negative test ran concurrently in the same
//  process. The presumed mechanism (a stale pre-call thread queue) was disproven by
//  `PortableTLSErrorQueueTests`; this suite reconstructs the field's *shape* instead and lets the
//  evidence speak: if any healthy receive ever classifies fatally again, the thrown error now
//  carries the drained queue, the connection, the thread, and the call (``TLSFailureEvidence``), so
//  a recurrence diagnoses itself.
//
//  The shape: one transport requiring client certificates, hammered by a storm of certificate-less
//  clients — every connect a failed `SSL_accept` classifying `PEER_DID_NOT_RETURN_A_CERTIFICATE`
//  somewhere in this process — while healthy echo sessions decrypt a dribbled payload under
//  concurrent receivers on the cooperative pool. Nothing here asserts a mechanism; the assertion is
//  the CONTRACT the field event violated: no healthy session fails, no byte is lost, however many
//  foreign handshakes die around it.
//
//  `HTTP_TLS_STRESS_ROUNDS` scales the healthy rounds (default keeps the suite fast; reproduction
//  runs crank it into the hundreds).
//
//  Standards: TLS 1.3 (RFC 8446) — §4.4.2.4 client-certificate requirement; BoringSSL
//  `include/openssl/err.h` (per-thread queue) and `include/openssl/ssl.h` (`SSL_get_error`).
//  CWE-488 (exposure of data element to wrong session) is the defect class being sentineled.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` — the opt-in portable build (`HTTP_PORTABLE_TLS`).
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

    @Suite(
        "Portable TLS — healthy sessions under a storm of failed foreign handshakes",
        .realNetwork
    )
    struct PortableTLSCrossConnectionStressTests {
        /// Concurrent receivers per healthy session — enough to keep the receive exclusion contended
        /// the way the field configuration (128 readers) kept it.
        private static let readers = 32

        /// Healthy echo rounds per run; `HTTP_TLS_STRESS_ROUNDS` cranks it for reproduction runs.
        private static var rounds: Int {
            ProcessInfo.processInfo.environment["HTTP_TLS_STRESS_ROUNDS"].flatMap(Int.init) ?? 4
        }

        @Test(
            "no healthy session inherits a foreign handshake's fatal error",
            .timeLimit(TestLivenessBudget.timeLimit(minutes: 5)))
        func healthySessionsSurviveTheStorm() async throws {
            let storm = try Storm()
            try await storm.start()
            defer { storm.stop() }

            // Give the storm a head start so the first healthy round already runs beside failing
            // handshakes rather than before them.
            try await Task.sleep(nanoseconds: 50_000_000)

            for round in 0 ..< Self.rounds {
                try await Self.oneHealthyRound(round: round)
            }

            await storm.shutdown()
            #expect(
                storm.surfacedConnections == 0,
                "the `.required` transport must never surface a certificate-less client"
            )
            // The storm must actually have poisoned: without a floor of REAL rejected handshakes —
            // each one a fatal `SSL_accept` classification leaving `PEER_DID_NOT_RETURN_A_CERTIFICATE`
            // on some thread — a green run would assert nothing about inheritance.
            #expect(
                storm.rejectedHandshakes >= Self.rounds,
                "only \(storm.rejectedHandshakes) foreign handshakes failed; the storm was becalmed"
            )
        }

        // MARK: - One healthy round

        /// One dribbled echo session: handshake, 32 concurrent receivers draining a balanced
        /// payload, multiset equality — the exact contract the field failure broke.
        private static func oneHealthyRound(round: Int) async throws {
            let harness = try EchoHarness()
            defer { harness.tearDown() }
            let payload = PortableTLSLoopback.balancedPayload(repeats: 16)
            harness.startClient(writing: payload, pieceOctets: 32, pauseMicros: 50)
            try await harness.connection.performHandshake()

            let collected = try await drainConcurrently(harness.connection, ceiling: 64)
            #expect(
                collected.count == payload.count,
                "round \(round) lost \(payload.count - collected.count) octet(s)"
            )
            #expect(
                PortableTLSLoopback.histogram(collected) == PortableTLSLoopback.histogram(payload)
            )
            await harness.connection.close()
        }

        /// Drains the connection concurrently until close_notify, pooling every receiver's octets.
        ///
        /// ``readers`` tasks receive at once; a fatal classification surfaces as the thrown evidence.
        private static func drainConcurrently(
            _ connection: PortableTLSConnection,
            ceiling: Int
        ) async throws -> [UInt8] {
            try await withThrowingTaskGroup(of: [UInt8].self) { group in
                for _ in 0 ..< readers {
                    group.addTask {
                        var mine: [UInt8] = []
                        while true {
                            let count = try await connection.receive(
                                into: &mine,
                                maxLength: ceiling
                            )
                            guard count > 0 else {
                                return mine
                            }
                        }
                    }
                }
                var all: [UInt8] = []
                for try await slice in group {
                    all.append(contentsOf: slice)
                }
                return all
            }
        }

        // MARK: - The storm

        /// A `.required` transport plus a relay of certificate-less clients, each connect provoking
        /// one server-side `SSL_accept` failure with `PEER_DID_NOT_RETURN_A_CERTIFICATE` — the exact
        /// entry the field report carried — for as long as the storm runs.
        private final class Storm: @unchecked Sendable {
            private let transport: PortableTLSTransport
            private let running = Atomic<Bool>(true)
            private let surfaced = Atomic<Int>(0)
            private let rejected = Atomic<Int>(0)
            private let clientsDone = DispatchSemaphore(value: 0)
            private var accepting: Task<Void, Never>?
            /// Parallel certificate-less client relays; more than one keeps a failed handshake in
            /// flight near-continuously.
            private static let relays = 3

            var surfacedConnections: Int { surfaced.load(ordering: .acquiring) }

            /// Handshakes the server provably refused — the storm's effectiveness oracle.
            var rejectedHandshakes: Int { rejected.load(ordering: .acquiring) }

            init() throws {
                var tls = try DevTLSIdentity.selfSigned()
                tls.clientAuth = .required
                transport = PortableTLSTransport(
                    configuration: TransportConfiguration(port: 0, backbone: .portableTLS, tls: tls)
                )
            }

            deinit {
                // `stop()` joins the relays; the transport is shut down in `shutdown()`.
            }

            func start() async throws {
                let connections = try await transport.start()
                accepting = Task { [self] in
                    for await connection in connections {
                        surfaced.wrappingAdd(1, ordering: .relaxed)
                        await connection.close()
                    }
                }
                let port = transport.boundPort
                for _ in 0 ..< Self.relays {
                    DispatchQueue.global(qos: .userInitiated)
                        .async { [self] in
                            defer { clientsDone.signal() }
                            while running.load(ordering: .acquiring) {
                                if Self.oneCertificatelessHandshake(port: port) {
                                    rejected.wrappingAdd(1, ordering: .relaxed)
                                }
                                // Paced either way: a relay that pours full-tilt parks thousands of
                                // loopback sockets in TIME_WAIT and exhausts the ephemeral range,
                                // after which every `connect(2)` fails and the storm goes silent —
                                // observed, not hypothetical. ~50 rejections/s/relay is storm enough.
                                usleep(20_000)
                            }
                        }
                }
            }

            /// One TCP connect + certificate-less `SSL_connect`: the server's `SSL_accept` fails
            /// with `PEER_DID_NOT_RETURN_A_CERTIFICATE`, mirrored to this client as a fatal alert.
            ///
            /// Returns whether the server provably refused the handshake. A TLS 1.3 client believes
            /// its handshake succeeded the moment it sends Finished (RFC 8446 §4.4.4 — the client's
            /// flight needs no acknowledgment), so `SSL_connect` returning `1` proves nothing here;
            /// the refusal is only visible to the `SSL_read` that collects the server's
            /// `certificate_required` alert (§4.4.2.4). A failed `connect(2)` never spoke TLS at all
            /// and counts for nothing.
            private static func oneCertificatelessHandshake(port: UInt16) -> Bool {
                let descriptor = CHTTPBoringSSLShims_connect_loopback(port)
                guard descriptor >= 0 else {
                    return false
                }
                defer { _ = close(descriptor) }
                // Bound the alert wait: on rejection the alert arrives in microseconds; the timeout
                // only matters if the server misbehaves by accepting, which the read then exposes.
                var patience = timeval(tv_sec: 2, tv_usec: 0)
                _ = setsockopt(
                    descriptor,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    &patience,
                    socklen_t(MemoryLayout<timeval>.size)
                )
                guard let context = CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_client_method())
                else {
                    return false
                }
                defer { CHTTPBoringSSL_SSL_CTX_free(context) }
                CHTTPBoringSSL_SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
                _ = CHTTPBoringSSLShims_set_client_alpn(context)
                guard let ssl = CHTTPBoringSSL_SSL_new(context) else {
                    return false
                }
                defer { CHTTPBoringSSL_SSL_free(ssl) }
                CHTTPBoringSSL_SSL_set_fd(ssl, descriptor)
                guard CHTTPBoringSSL_SSL_connect(ssl) == 1 else {
                    return true  // refused before the client even finished its flight
                }
                var probe: UInt8 = 0
                let outcome = withUnsafeMutableBytes(of: &probe) { raw in
                    CHTTPBoringSSL_SSL_read(ssl, raw.baseAddress, 1)
                }
                return outcome <= 0  // the alert; app data would mean the server accepted
            }

            /// Stops the client relays and joins them; safe to call more than once.
            func stop() {
                guard running.exchange(false, ordering: .acquiringAndReleasing) else {
                    return
                }
                for _ in 0 ..< Self.relays {
                    _ = clientsDone.wait(timeout: .now() + .seconds(10))
                }
            }

            func shutdown() async {
                stop()
                await transport.shutdown()
                accepting?.cancel()
            }
        }

        // MARK: - The healthy harness

        /// A handshaken server connection with a raw libssl client dribbling on the other end of a
        /// socket pair — the same shape `PortableTLSReceiveOwnershipTests` drives, self-contained so
        /// this suite owns its teardown order.
        private final class EchoHarness {
            let connection: PortableTLSConnection
            private let loop: TLSEventLoop
            private let serverContext: OpaquePointer
            private let clientDescriptor: Int32
            private let client: (ssl: OpaquePointer, context: OpaquePointer)
            private let finished = DispatchSemaphore(value: 0)
            private var startedClient = false

            init() throws {
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
                client = try PortableTLSLoopback.makeClient(descriptor: pair.client)
            }

            deinit {
                // Released in `tearDown()`, after the background client is joined.
            }

            /// Handshakes on a background thread, dribbles `bytes`, then sends close_notify.
            func startClient(writing bytes: [UInt8], pieceOctets: Int, pauseMicros: UInt32) {
                startedClient = true
                nonisolated(unsafe) let ssl = client.ssl
                let done = finished
                DispatchQueue.global(qos: .userInitiated)
                    .async {
                        defer { done.signal() }
                        guard CHTTPBoringSSL_SSL_connect(ssl) == 1 else {
                            return
                        }
                        var offset = 0
                        while offset < bytes.count {
                            let end = min(offset + max(1, pieceOctets), bytes.count)
                            let piece = Array(bytes[offset ..< end])
                            _ = piece.withUnsafeBytes {
                                CHTTPBoringSSL_SSL_write(ssl, $0.baseAddress, Int32($0.count))
                            }
                            offset = end
                            if pauseMicros > 0 {
                                usleep(pauseMicros)
                            }
                        }
                        _ = CHTTPBoringSSL_SSL_shutdown(ssl)
                    }
            }

            /// Joins the background client, then frees every handle in dependency order.
            func tearDown() {
                if startedClient {
                    _ = finished.wait(timeout: .now() + .seconds(10))
                }
                CHTTPBoringSSL_SSL_free(client.ssl)
                CHTTPBoringSSL_SSL_CTX_free(client.context)
                _ = close(clientDescriptor)
                CHTTPBoringSSL_SSL_CTX_free(serverContext)
                loop.stop()
            }
        }
    }

#endif
