//
//  FakeQUICConnection.swift
//  HTTPServerTests
//
//  An in-memory ``QUICConnection`` (RFC 9000) that yields scripted ``FakeQUICStream``s to the live
//  HTTP/3 server runtime. It stands in for a Network.framework QUIC handshake so a driver-level test
//  can control the *interleaving* of two peer streams — which is what the P0.3 blocked-QPACK
//  regression needs and what an end-to-end loopback client cannot express.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Synchronization

/// A ``QUICConnection`` over scripted in-memory streams, recording the server's own opened streams.
final class FakeQUICConnection: QUICConnection, @unchecked Sendable {
    let peer: TransportAddress
    let negotiatedApplicationProtocol: String? = "h3"

    private struct State {
        var opened: [FakeQUICStream] = []
        var nextServerUniID: UInt64 = 3  // RFC 9000 §2.1 — server-initiated unidirectional
        var closeCodes: [UInt64] = []
        var ticket: AdmissionTicket?
    }

    private let state = Mutex(State())
    private let inbound: AsyncStream<any QUICStream>
    private let continuation: AsyncStream<any QUICStream>.Continuation

    init(peer: TransportAddress = TransportAddress(host: "203.0.113.7", port: 4_433)) {
        self.peer = peer
        (self.inbound, self.continuation) = AsyncStream.makeStream()
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// The admission slot a charging listener took for this connection, for the server to adopt.
    var admissionTicket: AdmissionTicket? {
        state.withLock(\.ticket)
    }

    /// Attaches the slot a charging listener charged before yielding this connection.
    func adopt(_ ticket: AdmissionTicket) {
        state.withLock { $0.ticket = ticket }
    }

    /// Hands a peer-initiated stream to the server runtime.
    func accept(_ stream: FakeQUICStream) {
        continuation.yield(stream)
    }

    /// Ends the inbound-stream sequence, so the connection's serve loop can finish.
    func finish() {
        continuation.finish()
    }

    func inboundStreams() -> AsyncStream<any QUICStream> {
        inbound
    }

    // swiftlint:disable:next unneeded_throws_rethrows - the QUICConnection requirement is throwing
    func openStream(direction: QUICStreamDirection) async throws -> any QUICStream {
        state.withLock { current in
            let id = QUICStreamID(current.nextServerUniID)
            current.nextServerUniID += 4
            let stream = FakeQUICStream(id: id, direction: direction)
            current.opened.append(stream)
            return stream
        }
    }

    func close(errorCode: UInt64) async {
        state.withLock { $0.closeCodes.append(errorCode) }
        continuation.finish()
    }

    /// The server's own unidirectional streams (control + QPACK encoder/decoder), in open order.
    var openedStreams: [FakeQUICStream] {
        state.withLock(\.opened)
    }

    /// The QUIC application error codes this connection was closed with (RFC 9000 §19.19).
    var closeCodes: [UInt64] {
        state.withLock(\.closeCodes)
    }
}
