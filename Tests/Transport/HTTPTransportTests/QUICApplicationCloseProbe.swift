//
//  QUICApplicationCloseProbe.swift
//  HTTPTransportTests
//
//  A Network.framework QUIC client that reports the application error code its peer closed the
//  connection with. RFC 9000 §10.2 ends a connection with a CONNECTION_CLOSE frame, and the frame
//  type 0x1d variant (§19.19) carries the *application* error code the application protocol chose —
//  for HTTP/3 the RFC 9114 §8.1 code (H3_MISSING_SETTINGS, H3_FRAME_UNEXPECTED, …). Apple's stack
//  surfaces the code a peer sent through `NWProtocolQUIC.Metadata.applicationError`
//  (`nw_quic_get_application_error`: "the Application Error value received from the peer in a
//  connection close message", `UInt64.max` when none was received), which makes this client the
//  wire-level oracle the loopback tests need: it observes what h3spec observes, without h3spec.
//

import Foundation
import Network
import Synchronization

/// A loopback QUIC client that reports the application error its peer closes the connection with.
///
/// Dial with ``ready(within:)``, optionally ``send(_:)`` (no FIN) so a live stream is open at close
/// time — the shape a real HTTP/3 connection is in when the engine rejects a control stream — then
/// read ``observedCloseCode(within:)`` once the peer has closed (RFC 9000 §10.2 / §19.19).
final class QUICApplicationCloseProbe: @unchecked Sendable {
    /// What went wrong on the probe's side of the wire, as a diagnosis rather than a hang.
    enum Failure: Error {
        /// The awaited transition did not happen inside the deadline — the peer never closed (or
        /// never completed the handshake), which is itself a finding: a close that carries no
        /// CONNECTION_CLOSE at all is worse than one carrying code 0.
        case timedOut(String)
        /// The connection ended before the QUIC handshake completed.
        case closedBeforeReady
        /// Apple's stack exposed no QUIC metadata to read the peer's close code from.
        case noQUICMetadata
    }

    private let connection: NWConnection
    private let queue = DispatchQueue(label: "quic.close-code.probe")
    private let waiters = Mutex<Waiters>(Waiters())

    private struct Waiters {
        var isReady = false
        var isClosed = false
        var ready: CheckedContinuation<Void, any Error>?
        var closed: CheckedContinuation<Void, any Error>?
        /// The QUIC metadata captured at `.ready`, kept in case the failed connection stops
        /// vending metadata after teardown.
        var metadata: NWProtocolQUIC.Metadata?
    }

    /// Creates a probe that will dial `127.0.0.1:port` offering ALPN `h3` (RFC 9114 §3.1).
    init(port: UInt16) {
        let options = NWProtocolQUIC.Options(alpn: ["h3"])
        // The server under test uses the self-signed dev identity: accept it, loopback-only.
        sec_protocol_options_set_verify_block(
            options.securityProtocolOptions,
            { _, _, complete in complete(true) },
            DispatchQueue(label: "quic.close-code.probe.verify")
        )
        connection = NWConnection(
            host: "127.0.0.1",
            port: NWEndpoint.Port(rawValue: port) ?? .any,
            using: NWParameters(quic: options)
        )
    }

    deinit {
        connection.cancel()
    }

    /// Starts the client and waits for the QUIC handshake (RFC 9001) to complete.
    func ready(within seconds: Int) async throws {
        connection.stateUpdateHandler = { [weak self] state in
            self?.handle(state)
        }
        connection.start(queue: queue)
        expire(after: seconds, "QUIC handshake") { current in
            defer { current.ready = nil }
            return current.ready
        }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            let resumeNow: Bool = waiters.withLock { current in
                guard !current.isReady else {
                    return true
                }
                current.ready = continuation
                return false
            }
            if resumeNow {
                continuation.resume()
            }
        }
    }

    /// Sends `bytes` on the client's stream *without* FIN, so a live stream is open at close time.
    func send(_ bytes: [UInt8]) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: Data(bytes),
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    }
                    else {
                        continuation.resume()
                    }
                }
            )
        }
    }

    /// Waits for the peer to close, then reports the application error code it closed with.
    ///
    /// `UInt64.max` means the connection ended with **no** application close code at all
    /// (`nw_quic_get_application_error`'s "no error has been received").
    func observedCloseCode(within seconds: Int) async throws -> UInt64 {
        expire(after: seconds, "peer CONNECTION_CLOSE") { current in
            defer { current.closed = nil }
            return current.closed
        }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            let resumeNow: Bool = waiters.withLock { current in
                guard !current.isClosed else {
                    return true
                }
                current.closed = continuation
                return false
            }
            if resumeNow {
                continuation.resume()
            }
        }
        let metadata =
            connection.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata
            ?? waiters.withLock(\.metadata)
        guard let metadata else {
            throw Failure.noQUICMetadata
        }
        return metadata.applicationError.code
    }

    /// Tears the client down.
    func cancel() {
        connection.cancel()
    }

    // MARK: - Internals

    private func handle(_ state: NWConnection.State) {
        switch state {
            case .ready:
                let ready = waiters.withLock { current -> CheckedContinuation<Void, any Error>? in
                    current.isReady = true
                    current.metadata =
                        connection.metadata(definition: NWProtocolQUIC.definition)
                        as? NWProtocolQUIC.Metadata
                    defer { current.ready = nil }
                    return current.ready
                }
                ready?.resume()
            case .failed, .cancelled:
                let (ready, closed) = waiters.withLock { current -> (Waiter, Waiter) in
                    current.isClosed = true
                    defer {
                        current.ready = nil
                        current.closed = nil
                    }
                    return (current.ready, current.closed)
                }
                ready?.resume(throwing: Failure.closedBeforeReady)
                closed?.resume()
            default:
                break
        }
    }

    private typealias Waiter = CheckedContinuation<Void, any Error>?

    /// Arms a deadline that fails the pending waiter `take` selects, so a hang becomes a diagnosis.
    private func expire(
        after seconds: Int,
        _ event: String,
        _ take: @escaping @Sendable (inout Waiters) -> Waiter
    ) {
        queue.asyncAfter(deadline: .now() + .seconds(seconds)) { [weak self] in
            guard let waiter = self?.waiters.withLock({ take(&$0) }) else {
                return
            }
            waiter.resume(throwing: Failure.timedOut(event))
        }
    }
}
