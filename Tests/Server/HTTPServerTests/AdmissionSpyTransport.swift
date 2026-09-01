//
//  AdmissionSpyTransport.swift
//  HTTPServerTests
//
//  A ``ServerTransport`` that behaves like a real gated backbone: it charges an admission slot for
//  every inbound connection **before** it yields anything, attaches the ticket to the connection, and
//  closes a refused connection at the accept point instead of queueing it (audit F8). Standing in for
//  a socket backbone lets the server's half of the contract — adopt the ticket, never double-charge,
//  never create a serve task for a reject — be asserted without a real listener.
//

import HTTPTestSupport
import HTTPTransport
import Synchronization

/// An in-memory backbone that applies the admission gate at its accept point, like a socket backbone.
final class AdmissionSpyTransport: ServerTransport {
    /// The backbone identity (the in-memory fake).
    let backbone: TransportBackbone = .fake

    /// Always `0` — this transport binds no socket.
    let boundPort: UInt16 = 0

    /// Every connection the simulated accept loop saw, in arrival order — admitted and refused alike.
    let inbound: [AdmissionSpyConnection]

    /// The connections actually yielded into the accept stream (the admitted ones).
    var yielded: [TransportConnectionID] { accepted.withLock(\.self) }

    private let accepted = Mutex<[TransportConnectionID]>([])

    /// Creates a transport that will present `inbound` to the gate, in order.
    init(inbound: [AdmissionSpyConnection]) {
        self.inbound = inbound
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Charges a slot for each inbound connection before yielding it; refused ones are closed here.
    ///
    /// The accept stream stays `.unbounded` deliberately, for the same reason every real backbone's
    /// does: `AsyncStream`'s buffering policy *drops* on overflow, and a dropped connection is a leaked
    /// descriptor. The bound comes from the gate — a slot is charged before `yield`, so the stream's
    /// depth can never exceed the capacity's total.
    func start(admission: ConnectionAdmission?) async -> AsyncStream<any TransportConnection> {
        AsyncStream { [self] continuation in
            for connection in inbound {
                admit(connection, admission: admission, into: continuation)
            }
            continuation.finish()
        }
    }

    /// The simulated accept point: charge, then either yield or close — never both, never neither.
    private func admit(
        _ connection: AdmissionSpyConnection,
        admission: ConnectionAdmission?,
        into continuation: AsyncStream<any TransportConnection>.Continuation
    ) {
        guard let admission else {
            accepted.withLock { $0.append(connection.id) }
            continuation.yield(connection)
            return
        }
        switch admission.admit(host: connection.peer.host) {
            case .admitted(let ticket, _):
                connection.attach(ticket)
                accepted.withLock { $0.append(connection.id) }
                continuation.yield(connection)
            case .rejectedTotal, .rejectedHost:
                // The socket backbone's `close(fd)`: refused before anything is queued, so no serve
                // task is ever created for it.
                connection.refuse()
        }
    }

    /// Yields the seeded connections with no gate — the non-throwing shim, as on ``FakeTransport``.
    func start() async -> AsyncStream<any TransportConnection> {
        await start(admission: nil)
    }

    /// A no-op for the in-memory transport.
    func shutdown() async {
        // No-op: the in-memory transport holds no resources to release.
    }
}
