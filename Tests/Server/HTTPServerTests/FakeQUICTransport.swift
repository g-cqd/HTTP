//
//  FakeQUICTransport.swift
//  HTTPServerTests
//
//  An in-memory ``QUICServerTransport`` that yields scripted ``FakeQUICConnection``s, so the server's
//  own QUIC accept path — admission, the shutdown registry, drain — can be driven without a real UDP
//  listener. It models both backbone shapes: `charging: true` charges the shared
//  ``ConnectionAdmission`` before yielding (what the Network.framework backbones do), `false` leaves
//  the connection unticketed (an ungated listener), so the server's own fallback charge is exercised.
//

import HTTPTransport
import Synchronization

/// A scripted QUIC listener over in-memory connections.
final class FakeQUICTransport: QUICServerTransport, @unchecked Sendable {
    let boundPort: UInt16 = 4_433
    /// The endpoint this fake "bound" — loopback on its fixed port, so the server's `Alt-Svc`
    /// advertisement (RFC 7838) reads the realized endpoint here exactly as it does on a real
    /// listener (audit F-04).
    let boundEndpoint: BindEndpoint? = BindEndpoint(
        address: "127.0.0.1",
        family: .ipv4,
        port: 4_433
    )
    /// Whether this listener charges the admission gate itself before yielding a connection.
    private let charging: Bool

    private let gate = Mutex<ConnectionAdmission?>(nil)
    private let inbound: AsyncStream<any QUICConnection>
    private let continuation: AsyncStream<any QUICConnection>.Continuation
    private let refusals = Mutex<Int>(0)

    init(charging: Bool = false) {
        self.charging = charging
        (self.inbound, self.continuation) = AsyncStream.makeStream()
    }

    deinit {
        // No teardown beyond ARC.
    }

    // swiftlint:disable:next unneeded_throws_rethrows - the QUICServerTransport requirement throws
    func start(admission: ConnectionAdmission?) async throws -> AsyncStream<any QUICConnection> {
        gate.withLock { $0 = admission }
        return inbound
    }

    func shutdown() async {
        continuation.finish()
    }

    /// Offers a connection to the server, charging it first when this listener is a charging one.
    func accept(_ connection: FakeQUICConnection) {
        guard charging, let admission = gate.withLock(\.self) else {
            continuation.yield(connection)
            return
        }
        switch admission.admit(host: connection.peer.host) {
            case .admitted(let ticket, _):
                connection.adopt(ticket)
                continuation.yield(connection)
            case .rejectedTotal, .rejectedHost:
                refusals.withLock { $0 += 1 }  // the transport-side refusal, before any serve task
        }
    }

    /// How many connections this listener refused at the gate.
    var refusalCount: Int {
        refusals.withLock(\.self)
    }
}
