//
//  HTTPServerHTTP3UnblockRaceTests.swift
//  HTTPServerTests
//
//  R5-P0b — the QPACK-unblock race (RFC 9204 §2.1.2).
//
//  A request whose field section references a not-yet-received insert is buffered, and it surfaces
//  later from the **encoder stream's** receive — on a different task than the one reading the request
//  stream. Three things therefore happen concurrently on every blocked request:
//
//    (E) the engine clears the stream's blocked state,
//    (R) the routed `request` event reaches the registry,
//    (D) the request stream's driver decides the stream no longer needs a registry entry.
//
//  The previous round added an explicit wake path and tested the one ordering its fixture produced —
//  (D) before (E). The orderings it did not produce are the ones that lose the request: with (E) split
//  from (R) by a suspension point, (D) reads "no longer blocked", drops the entry, and the event then
//  arrives for a stream nobody is tracking; or (R) lands first and (D) drops the entry *with the
//  mailbox in it*.
//
//  These tests pin the structure rather than a schedule. (E) and (R) are one engine-isolated step, so
//  they cannot be observed apart; and the registry refuses to drop a non-empty mailbox whatever (D)
//  asks. The parameterized cases below enumerate what is left, and the racing case runs the real driver
//  with the two events deliberately unordered.
//
//  Standards: RFC 9204 §2.1.2 (blocked streams), §4.5 (field-section prefix); RFC 9114 §4.1, §8.1.
//

import HTTP3
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Testing

@testable import HTTPServer

@Suite("HTTP/3 — the QPACK-unblock race cannot be lost (R5-P0b)")
struct HTTPServerHTTP3UnblockRaceTests {
    private static let requestStream = QUICStreamID(0)
    private static let secondStream = QUICStreamID(4)
    private static let encoderStream = QUICStreamID(6)

    /// Where the driver's end-of-driving decision falls relative to the engine step that unblocks the
    /// request and files it (RFC 9204 §2.1.2).
    ///
    /// There is no third position. Filing happens inside the engine actor, in the same critical section
    /// as the receive that cleared the blocked state, so "cleared but not yet filed" is not a state any
    /// other task can observe.
    enum Interleaving: String, CaseIterable, Sendable {
        /// The driver ends first: the engine still reports the section blocked.
        case concludeBeforeUnblock
        /// The engine unblocks and files first: the registry sees a filled mailbox.
        case concludeAfterUnblock
    }

    @Test(
        "the routed request survives whichever side of the unblock the driver ends on",
        arguments: Interleaving.allCases
    )
    func theRoutedRequestSurvivesEitherOrdering(_ interleaving: Interleaving) async throws {
        let server = try Self.makeServer()
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 20)
        let engine = Self.makeEngine()
        let request = FakeQUICStream(id: Self.requestStream, direction: .bidirectional)
        registry.register(request)

        // The request blocks: its `:authority` indexes an insert that has not arrived (RFC 9204 §4.5).
        let blocked = await engine.receive(
            Self.requestStream,
            Self.headersFrame(Self.blockedFieldSection),
            fin: true,
            routingInto: registry
        )
        #expect(blocked.own.isEmpty, "a blocked section surfaces nothing on its own stream")

        var concluded: Bool?
        if interleaving == .concludeBeforeUnblock {
            concluded = await server.concludeHTTP3Driving(
                Self.requestStream, registry: registry, engine: engine
            )
        }
        // (E) and (R) together: the insert clears the blocked state and files the request in one step.
        _ = await engine.receive(
            Self.encoderStream,
            [0x02] + Self.insertAuthority,
            fin: false,
            routingInto: registry
        )
        if interleaving == .concludeAfterUnblock {
            concluded = await server.concludeHTTP3Driving(
                Self.requestStream, registry: registry, engine: engine
            )
        }

        #expect(concluded == true, "the entry must be kept for the dispatcher, not dropped")
        #expect(registry.writer(for: Self.requestStream) != nil, "the writer must stay reachable")
        // The whole point: the request is still deliverable, on the stream it belongs to.
        let mail = registry.takeMailbox(Self.requestStream)
        #expect(mail.count == 1)
        guard case .request(let id, _, _) = mail.first else {
            Issue.record("the routed batch is not the unblocked request: \(mail)")
            return
        }
        #expect(id == Self.requestStream)
    }

    @Test("the engine files a routed batch before its receive returns, not after")
    func routingHappensInsideTheEngineStep() async {
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 20)
        let engine = Self.makeEngine()
        let request = FakeQUICStream(id: Self.requestStream, direction: .bidirectional)
        registry.register(request)

        _ = await engine.receive(
            Self.requestStream,
            Self.headersFrame(Self.blockedFieldSection),
            fin: true,
            routingInto: registry
        )
        let unblocking = await engine.receive(
            Self.encoderStream,
            [0x02] + Self.insertAuthority,
            fin: false,
            routingInto: registry
        )

        // Nothing for another stream comes *back* — it has already been filed. That is what removes
        // the window a concurrent `concludeHTTP3Driving` used to fall into.
        #expect(unblocking.own.isEmpty, "a foreign event must never be handed back to the caller")
        #expect(unblocking.overflowed.isEmpty)
        #expect(registry.takeMailbox(Self.requestStream).count == 1)
    }

    @Test("a mailbox that already holds mail is never dropped by the end of driving")
    func aFilledMailboxIsNeverDropped() async throws {
        let server = try Self.makeServer()
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 20)
        let engine = Self.makeEngine()
        let request = FakeQUICStream(id: Self.requestStream, direction: .bidirectional)
        registry.register(request)

        // Deposited without the engine ever having been blocked, so `retain` is unambiguously false —
        // the queue alone has to keep the entry alive.
        let deposited = registry.deposit(
            [.requestEnd(streamID: Self.requestStream)],
            for: Self.requestStream
        )
        #expect(Self.isQueued(deposited))
        let kept = await server.concludeHTTP3Driving(
            Self.requestStream, registry: registry, engine: engine
        )

        #expect(kept, "an entry with undelivered mail is owed to somebody")
        #expect(registry.takeMailbox(Self.requestStream).count == 1)
    }

    @Test("an entry with neither mail nor a blocked section is still retired")
    func anIdleEntryIsStillRetired() async throws {
        let server = try Self.makeServer()
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 20)
        let engine = Self.makeEngine()
        registry.register(FakeQUICStream(id: Self.requestStream, direction: .bidirectional))

        let kept = await server.concludeHTTP3Driving(
            Self.requestStream, registry: registry, engine: engine
        )

        // The bound the retention rule exists to preserve: a long-lived connection that opens streams
        // sequentially must not keep an entry per stream it has served (CWE-770).
        #expect(!kept)
        #expect(registry.isEmpty)
    }

    @Test("racing the insert against the request's FIN never loses a request")
    func racingTheInsertAgainstTheFinNeverLosesARequest() async throws {
        // The interleaving is left to the scheduler on purpose, and repeated: the assertion is that
        // *every* outcome answers the request, so any ordering that dropped it fails this test.
        for round in 0 ..< 40 {
            let handled = AsyncEventProbe<String>()
            let server = try Self.makeServer(handled)
            let quic = FakeQUICConnection()
            let serving = Task { await server.serveHTTP3(quic) }
            defer { serving.cancel() }

            let encoder = FakeQUICStream(id: Self.encoderStream, direction: .unidirectional)
            let request = FakeQUICStream(id: Self.requestStream, direction: .bidirectional)
            let second = FakeQUICStream(id: Self.secondStream, direction: .bidirectional)
            quic.accept(encoder)
            quic.accept(request)
            quic.accept(second)
            encoder.deliver([0x02], fin: false)

            // Two blocked requests and the insert that unblocks them, released concurrently: the
            // request streams' drivers reach their end-of-driving decision while the encoder task is
            // inside the engine step that clears their blocked state.
            let headers = Self.headersFrame(Self.blockedFieldSection)
            await withDiscardingTaskGroup { group in
                group.addTask { request.deliver(headers, fin: true) }
                group.addTask { second.deliver(headers, fin: true) }
                group.addTask { encoder.deliver(Self.insertAuthority, fin: false) }
            }

            _ = try await handled.wait(forAtLeast: 2)
            #expect(handled.count == 2, "round \(round) lost a request")
            #expect(request.resetCodes.isEmpty, "round \(round) reset the request stream")
            #expect(second.resetCodes.isEmpty, "round \(round) reset the second stream")
        }
    }

    // MARK: - Fixtures

    /// A bare connection engine, driven directly so an ordering can be stated instead of raced.
    private static func makeEngine() -> HTTPServer<ContinuousClock>.Engine {
        let unmatched: @Sendable (QUICStreamID, HTTPRequest) -> RequestBodyPolicy = { _, _ in
            .unmatched
        }
        return HTTPServer<ContinuousClock>
            .Engine(
                limits: .default,
                enableConnectProtocol: false,
                resolveRoute: unmatched
            )
    }

    private static func makeServer(
        _ handled: AsyncEventProbe<String> = AsyncEventProbe()
    ) throws -> HTTPServer<ContinuousClock> {
        let responder = ClosureResponder { request, _, _ in
            handled.record(request.path)
            return ServerResponse(HTTPResponse(status: .ok), body: [])
        }
        let configuration = TransportConfiguration(port: 0, backbone: .fake)
        return HTTPServer(
            transport: try TransportFactory.make(configuration),
            responder: responder
        )
    }

    /// A request field section with prefix RIC=1/Base=0 whose `:authority` is a dynamic reference —
    /// blocked until ``insertAuthority`` arrives on the encoder stream (RFC 9204 §4.5).
    private static let blockedFieldSection: [UInt8] = [0x02, 0x00, 0xD1, 0xD7, 0xC1, 0x80]

    /// The encoder-stream instruction inserting `:authority: dyn.example` (a static name reference).
    private static var insertAuthority: [UInt8] {
        var out: [UInt8] = []
        QPACKInteger.encode(0, prefixBits: 6, firstByte: 0xC0, into: &out)
        QPACKString.encode(Array("dyn.example".utf8), prefixBits: 7, into: &out)
        return out
    }

    /// A HEADERS frame (RFC 9114 §7.2.2) carrying `section`.
    private static func headersFrame(_ section: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        QUICVarint.encode(0x01, into: &out)
        QUICVarint.encode(UInt64(section.count), into: &out)
        out.append(contentsOf: section)
        return out
    }

    private static func isQueued(_ deposit: HTTP3StreamRegistry.Deposit) -> Bool {
        if case .queued = deposit {
            return true
        }
        return false
    }
}
