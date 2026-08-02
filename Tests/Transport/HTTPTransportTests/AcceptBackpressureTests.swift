//
//  AcceptBackpressureTests.swift
//  HTTPTransportTests
//
//  Accept-time backpressure across the POSIX backbones (audit F8). Two distinct behaviors are pinned
//  against real loopback sockets, because the whole point of the finding is that the ceiling must bite
//  at `accept(2)` and not after a task has been spawned:
//
//   - The GLOBAL ceiling suspends the listener. A saturated transport stops re-arming its accept
//     source entirely, so the excess connections stay in the kernel's `listen(2)` backlog instead of
//     being drained into an unbounded queue; freeing slots re-arms it and the backlog drains.
//   - The PER-HOST ceiling does not. A refused connection is closed at the accept point — the client
//     sees EOF rather than hanging — while the listener keeps draining, so one abusive source cannot
//     deny service to everyone else.
//
//  PORTABLE ON PURPOSE. `AcceptGate` — the type both behaviors are properties of — is SHARED by all
//  five POSIX accept loops, `.posixEpoll` among them, so the Linux accept-backpressure path was
//  untested rather than absent while this file sat in the Linux exclusion list. What kept it out was
//  never the assertions: it was `internal import Darwin`, a `Darwin.`-qualified `close`, the dialer
//  living in the Network.framework-bound `LoopbackSupport.swift`, and a backbone list naming four
//  Darwin-only backbones. All four are fixture, so all four are `#if`-selected here and the two test
//  bodies below are unchanged — the `ConnectionDirectionOwnershipTests` shape, and for the same reason:
//  a separate Linux mirror is a second copy of an oracle, and second copies drift.
//
//  Standards: `accept(2)`/`listen(2)` per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP (RFC 9293) over
//  IPv4 (RFC 791). A resource-exhaustion defense in the spirit of RFC 9110 §15.5.30 (429) — CWE-770,
//  CWE-400.
//

#if canImport(Darwin) || canImport(Glibc)

    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif

    import HTTPTestSupport
    import Synchronization
    import Testing

    @testable import HTTPTransport

    @Suite("Accept backpressure — the ceiling bites at accept(2) (audit F8)", .realNetwork)
    struct AcceptBackpressureTests {
        /// The backbones whose accept paths route through the shared `AcceptGate` on this platform.
        ///
        /// Darwin exercises four. `.networkFramework` has no readiness source to leave un-armed, so it
        /// throttles with `NWListener.newConnectionLimit` instead — a different mechanism, the same two
        /// observable behaviors.
        ///
        /// Linux exercises `.posixEpoll`, the mirror of `.posixKqueue`: same accept-loop shape, same
        /// `AcceptGate`, same three `Outcome` arms, and a refusal closed with a direct `close(2)` on the
        /// accept loop, which is what makes the per-host EOF assertion hold there too. `.portableTLS` uses
        /// the gate as well but is deliberately absent from both lists — it is behind `HTTP_PORTABLE_TLS`
        /// and its ceiling is pinned by `HandshakeAdmissionTests`.
        #if canImport(Darwin)
            static let gatedBackbones: [TransportBackbone] = [
                .posixKqueue, .posixDispatch, .swiftSystem, .networkFramework
            ]
        #else
            static let gatedBackbones: [TransportBackbone] = [.posixEpoll]
        #endif

        @Test(
            "at the global ceiling the transport stops accepting, and resumes when slots free",
            .timeLimit(.minutes(1)),
            arguments: gatedBackbones
        )
        func suspendsAtCapacityAndResumes(_ backbone: TransportBackbone) async throws {
            let capacity = 4
            let gate = ConnectionAdmission(
                capacity: ConnectionAdmission.Capacity(total: capacity, perHost: 1_000)
            )
            let transport = try Self.makeTransport(backbone)
            let stream = try await transport.start(admission: gate)
            let port = transport.boundPort
            #expect(port != 0)

            let accepted = AcceptCollector()
            let collector = Task { await accepted.drain(stream) }
            // Three times the ceiling, so there is still a backlog to drain after the resume even if the
            // backbone refused a connection or two at the moment it saturated.
            let clients = (0 ..< capacity * 3).map { _ in openLoopbackConnection(to: port) }
            defer {
                for client in clients {
                    close(client)
                }
            }

            _ = try await accepted.probe.wait(forAtLeast: capacity)
            // Settle: if the transport were still draining into the stream, the excess would land here.
            // A negative ("nothing more arrives") cannot be awaited on a probe, so this is a bounded wait.
            try await Task.sleep(for: .milliseconds(300))
            #expect(
                accepted.probe.count == capacity, "the accept stream carried more than the ceiling")
            #expect(gate.counts.total == capacity)
            #expect(gate.isSaturated, "the gate must be latched so the transport stays suspended")

            // Free every slot: the gate crosses its hysteresis watermark and re-arms the accept source,
            // which then drains the connections still sitting in the listen(2) backlog.
            await accepted.releaseAll()
            _ = try await accepted.probe.wait(forAtLeast: capacity * 2)
            #expect(accepted.probe.count >= capacity * 2)

            collector.cancel()
            await transport.shutdown()
            _ = await collector.value
        }

        @Test(
            "a per-host rejection is closed at accept time and never yielded, and draining continues",
            .timeLimit(.minutes(1)),
            arguments: gatedBackbones
        )
        func perHostRejectionClosesAtAcceptTime(_ backbone: TransportBackbone) async throws {
            // Every loopback client shares the host "127.0.0.1", so the per-host ceiling is what bites;
            // the global one is far away, which is exactly the case that must NOT suspend the listener.
            let capacity = 4
            let gate = ConnectionAdmission(
                capacity: ConnectionAdmission.Capacity(total: 10_000, perHost: capacity)
            )
            let transport = try Self.makeTransport(backbone)
            let stream = try await transport.start(admission: gate)
            let port = transport.boundPort
            #expect(port != 0)

            let accepted = AcceptCollector()
            let collector = Task { await accepted.drain(stream) }
            let clients = (0 ..< capacity * 2).map { _ in openLoopbackConnection(to: port) }
            defer {
                for client in clients {
                    close(client)
                }
            }

            _ = try await accepted.probe.wait(forAtLeast: capacity)
            // Bounded wait: nothing more may be yielded.
            try await Task.sleep(for: .milliseconds(300))

            #expect(
                accepted.probe.count == capacity, "a refused connection reached the accept stream")
            #expect(!gate.isSaturated, "a per-host rejection must not suspend the accept source")

            // The four refused connections were closed on the accept loop — their clients see EOF, not a
            // hang, which is the difference between "refused" and "queued forever".
            let eofCount = clients.filter { Self.readsEOF($0) }.count
            #expect(eofCount == capacity, "the refused connections were not closed at accept time")

            collector.cancel()
            await transport.shutdown()
            _ = await collector.value
        }

        // MARK: - Helpers

        private static func makeTransport(
            _ backbone: TransportBackbone
        ) throws -> any ServerTransport {
            try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: backbone, eventLoopCount: 1)
            )
        }

        /// Whether `descriptor` reads end-of-stream within a short receive timeout.
        ///
        /// `read` returning 0 is EOF (the server closed); `-1` with the timeout is a still-open connection.
        private static func readsEOF(_ descriptor: Int32) -> Bool {
            guard descriptor >= 0 else {
                return false
            }
            var timeout = timeval(tv_sec: 0, tv_usec: 300_000)
            setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &timeout,
                socklen_t(MemoryLayout<timeval>.size)
            )
            var byte: UInt8 = 0
            return read(descriptor, &byte, 1) == 0
        }
    }

#endif
