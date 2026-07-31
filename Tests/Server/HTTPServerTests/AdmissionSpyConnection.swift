//
//  AdmissionSpyConnection.swift
//  HTTPServerTests
//
//  A ``TransportConnection`` that records whether the server ever *read* from it — the observable
//  proxy for "a serve task was created for this connection" (audit F8). A connection refused by the
//  admission gate must be closed without a single `receive`, so `wasRead == false` on every reject is
//  the finding's core claim in assertable form.
//

import HTTPTestSupport
import HTTPTransport
import Synchronization

/// A ``TransportConnection`` that records its reads and closes, parks the serve loop, and carries an
/// admission ticket the transport attaches at accept time.
final class AdmissionSpyConnection: TransportConnection {
    let id: TransportConnectionID
    let peer: TransportAddress

    /// The slot a gated transport charged for this connection before yielding it, attached after
    /// construction because the spy transport builds the connection to hand the ticket to.
    var admissionTicket: AdmissionTicket? { ticket.withLock(\.self) }

    private let ticket = Mutex<AdmissionTicket?>(nil)
    private let events = Mutex<Events>(Events())
    /// Never opened: a `receive` parks here so an admitted connection holds its slot for the whole
    /// test, exactly as a live keep-alive connection would.
    private let park = AsyncGate()
    /// Records the first admission decision — a read (admitted) or a close (refused) — so a test can
    /// await every decision instead of guessing with a sleep.
    private let probe: AsyncEventProbe<TransportConnectionID>?

    private struct Events {
        var wasRead = false
        var isClosed = false
        var decided = false
    }

    /// Creates a spy connection for `peer`, reporting its admission decision to `probe`.
    init(
        id: TransportConnectionID,
        peer: TransportAddress,
        probe: AsyncEventProbe<TransportConnectionID>? = nil
    ) {
        self.id = id
        self.peer = peer
        self.probe = probe
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Attaches the admission slot a gated transport charged for this connection.
    func attach(_ ticket: AdmissionTicket) {
        self.ticket.withLock { $0 = ticket }
    }

    /// Whether the server ever read from this connection — i.e. whether a serve task ran for it.
    var wasRead: Bool { events.withLock(\.wasRead) }

    /// Whether the connection has been closed.
    var isClosed: Bool { events.withLock(\.isClosed) }

    // MARK: TransportConnection

    /// Records the read (the connection was admitted and served), then parks until cancelled.
    func receive(maxLength _: Int) async throws -> [UInt8]? {
        recordRead()
        try await park.waitUntilOpen()  // never opened → suspends until the serve task is cancelled
        return nil
    }

    /// Discards sent bytes.
    func send(_: [UInt8]) async {
        // No-op: nothing in these tests inspects the wire.
    }

    /// Records the close (a refused connection is closed without ever being read).
    func close() async {
        refuse()
    }

    /// The synchronous close a transport performs on a refused connection — the fd `close(2)` at the
    /// accept point, before anything is queued.
    func refuse() {
        let decided = events.withLock { events -> Bool in
            events.isClosed = true
            defer { events.decided = true }
            return events.decided
        }
        if !decided {
            probe?.record(id)
        }
    }

    private func recordRead() {
        let decided = events.withLock { events -> Bool in
            events.wasRead = true
            defer { events.decided = true }
            return events.decided
        }
        if !decided {
            probe?.record(id)
        }
    }
}
