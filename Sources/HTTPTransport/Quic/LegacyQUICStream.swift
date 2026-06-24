//
//  LegacyQUICStream.swift
//  HTTPTransport
//
//  The legacy (macOS 15 floor) QUIC stream: one stream of an `NWProtocolQUIC` connection is an
//  `NWConnection`, whose callback `receive`/`send` are bridged to async. QUIC's end-of-stream is the
//  `isComplete` flag on a receive — surfaced as `fin` so the HTTP/3 engine sees a positive end-of-body
//  (RFC 9114 §4 / §7.1) — and FIN is sent as `isComplete: true` on a send (RFC 9000 §2).
//

internal import Foundation
internal import HTTPCore
internal import Network
internal import Synchronization

/// A ``QUICStream`` backed by a single-stream Network.framework `NWConnection` (legacy backbone).
///
/// `NWConnection`'s `send`/`receive`/`cancel` are documented thread-safe and this wrapper adds only a
/// small `Mutex`-guarded "finished" latch, so it is safe to share — hence `@unchecked Sendable`.
final class LegacyQUICStream: QUICStream, @unchecked Sendable {
    let id: QUICStreamID
    let direction: QUICStreamDirection
    private let connection: NWConnection
    /// Set once the peer's FIN has been surfaced, so a subsequent ``receive()`` reports end-of-stream.
    private let finished = Mutex<Bool>(false)

    init(id: QUICStreamID, direction: QUICStreamDirection, connection: NWConnection) {
        self.id = id
        self.direction = direction
        self.connection = connection
    }

    deinit {
        // No teardown beyond ARC.
    }

    func receive() async throws -> (bytes: [UInt8], fin: Bool)? {
        if finished.withLock(\.self) {
            return nil
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.receive(
                    minimumIncompleteLength: 1,
                    maximumLength: 65_535
                ) { [self] data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: error)
                        return
                    }
                    if isComplete {
                        finished.withLock { $0 = true }
                    }
                    continuation.resume(returning: ([UInt8](data ?? Data()), isComplete))
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func send(_ bytes: [UInt8], fin: Bool) async throws {
        let stream = connection
        // QUIC's stream FIN rides the `.finalMessage` content context (its `isFinal`), not `isComplete`
        // alone, so the peer sees end-of-stream (RFC 9000 §2).
        let context: NWConnection.ContentContext = fin ? .finalMessage : .defaultMessage
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            stream.send(
                content: bytes.isEmpty ? nil : Data(bytes),
                contentContext: context,
                isComplete: fin,
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

    func reset(errorCode _: UInt64) {
        // The legacy NWConnection stream API has no per-stream error code; cancelling sends RESET_STREAM.
        connection.cancel()
    }
}
