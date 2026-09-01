//
//  AcceptCollector.swift
//  HTTPTransportTests
//
//  Drains a transport's accept stream, keeping every yielded connection (and therefore its admission
//  ticket) alive so the gate stays charged while a backpressure test inspects it — then releases them
//  all on demand, which is what drives the gate past its hysteresis watermark.
//

import HTTPTestSupport
import HTTPTransport
import Synchronization
import Testing

/// A drain-and-hold sink for a transport's accept stream.
final class AcceptCollector: Sendable {
    /// Records each yielded connection so a test can await "at least N accepted" without sleeping.
    let probe = AsyncEventProbe<TransportConnectionID>()

    private let connections = Mutex<[any TransportConnection]>([])

    /// Creates an empty collector.
    init() {
        // Nothing to seed: the probe and the connection list start empty.
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Consumes `stream` until it finishes or the task is cancelled, holding every connection.
    func drain(_ stream: AsyncStream<any TransportConnection>) async {
        for await connection in stream {
            connections.withLock { $0.append(connection) }
            probe.record(connection.id)
        }
    }

    /// Releases every held connection's admission slot and closes it.
    func releaseAll() async {
        let held = connections.withLock { current in
            defer { current.removeAll() }
            return current
        }
        for connection in held {
            connection.admissionTicket?.release()
            await connection.close()
        }
    }
}
