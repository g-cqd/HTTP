//
//  LegacyQUICConnection.swift
//  HTTPTransport
//
//  The legacy (macOS 15 floor) QUIC connection: a Network.framework `NWConnectionGroup` per QUIC
//  connection (RFC 9000). Each inbound, peer-initiated stream arrives at the group's
//  `newConnectionHandler` as an `NWConnection`; the server opens its own streams — the HTTP/3 control
//  and QPACK unidirectional streams — with `NWConnection(from:using:)`, setting the §6.2 directionality
//  through `NWProtocolQUIC.Options.direction`. The QUIC stream identifier comes from the stream's
//  `NWProtocolQUIC.Metadata`.
//

internal import Foundation
internal import HTTPCore
internal import Network
internal import Synchronization

/// A ``QUICConnection`` backed by a Network.framework `NWConnectionGroup` (legacy backbone).
final class LegacyQUICConnection: QUICConnection, @unchecked Sendable {
    let peer: TransportAddress
    let negotiatedApplicationProtocol: String?

    /// The admission slot charged for this connection at accept time (audit F8).
    ///
    /// Surfaced so the server *adopts* it rather than charging a second slot for the same peer, and
    /// releases it promptly when the serve loop ends; `deinit` remains the backstop for a connection
    /// that is never served (audit addendum P0.5).
    let admissionTicket: AdmissionTicket?

    private let group: NWConnectionGroup
    private let queue: DispatchQueue
    private let inbound: AsyncStream<any QUICStream>
    private let continuation: AsyncStream<any QUICStream>.Continuation

    init(
        group: NWConnectionGroup,
        queue: DispatchQueue,
        peer: TransportAddress,
        negotiatedApplicationProtocol: String?,
        admissionTicket: AdmissionTicket? = nil
    ) {
        self.group = group
        self.queue = queue
        self.peer = peer
        self.negotiatedApplicationProtocol = negotiatedApplicationProtocol
        self.admissionTicket = admissionTicket
        (self.inbound, self.continuation) = AsyncStream.makeStream()
        group.newConnectionHandler = { [weak self] streamConnection in
            self?.acceptInbound(streamConnection)
        }
        group.stateUpdateHandler = { [weak self] state in
            switch state {
                case .cancelled, .failed:
                    self?.continuation.finish()
                default:
                    break
            }
        }
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Starts the underlying connection group on its queue.
    func start() {
        group.start(queue: queue)
    }

    func inboundStreams() -> AsyncStream<any QUICStream> {
        inbound
    }

    func openStream(direction: QUICStreamDirection) async throws -> any QUICStream {
        let options = NWProtocolQUIC.Options()
        options.direction = direction == .unidirectional ? .unidirectional : .bidirectional
        guard let streamConnection = NWConnection(from: group, using: options) else {
            throw TransportError.ioFailed("could not open a QUIC stream from the connection group")
        }
        try await waitUntilReady(streamConnection)
        guard let stream = Self.wrap(streamConnection) else {
            streamConnection.cancel()
            throw TransportError.ioFailed("opened QUIC stream exposed no metadata")
        }
        return stream
    }

    /// Closes the whole connection (RFC 9000 §10.2), recording the RFC 9114 §8.1 application error
    /// code in the tunnel's QUIC state before teardown.
    ///
    /// Best-effort by platform constraint, not by choice: `nw_quic_set_application_error` writes the
    /// code into live, shared QUIC state (a fresh metadata copy reads it back), but **no**
    /// Network.framework teardown path puts it on the wire — `NWConnectionGroup.cancel()` closes
    /// abortively with no CONNECTION_CLOSE frame type 0x1d (§19.19) at all, in either direction, on
    /// either backbone. Measured, with the wire observed by a second Network.framework client; the
    /// probe is `closeCarriesTheApplicationErrorCode` in `LegacyQUICTransportTests`, and the full
    /// experiment matrix is in docs/standards/CONFORMANCE.md. The write stays so the day Apple's
    /// stack consults it, the pinned probe flags the change and the wire gets the mandated code.
    ///
    /// The reason string must be **non-nil**: with `nil`, `nw_quic_set_application_error` crashes in
    /// `strlen(NULL)` (measured on macOS 27.0 — the crash that a previous attempt misread as "the
    /// connection stops closing"). It stays empty because RFC 9000 §10.2.3 cautions that reason
    /// phrases can disclose internal state.
    func close(errorCode: UInt64) async {
        if let metadata = group.metadata(definition: NWProtocolQUIC.definition)
            as? NWProtocolQUIC.Metadata
        {
            metadata.applicationError = .init(code: errorCode, reason: "")
        }
        group.cancel()
    }

    // MARK: - Internals

    private func acceptInbound(_ streamConnection: NWConnection) {
        streamConnection.stateUpdateHandler = { [weak self] state in
            guard let self else {
                return
            }
            switch state {
                case .ready:
                    streamConnection.stateUpdateHandler = nil
                    if let stream = Self.wrap(streamConnection) {
                        continuation.yield(stream)
                    }
                    else {
                        streamConnection.cancel()
                    }
                case .failed, .cancelled:
                    streamConnection.stateUpdateHandler = nil
                default:
                    break
            }
        }
        streamConnection.start(queue: queue)
    }

    /// Wraps a ready `NWConnection` stream, reading its QUIC stream identifier from the metadata.
    private static func wrap(_ connection: NWConnection) -> LegacyQUICStream? {
        guard
            let metadata = connection.metadata(definition: NWProtocolQUIC.definition)
                as? NWProtocolQUIC.Metadata
        else {
            return nil
        }
        let id = QUICStreamID(metadata.streamIdentifier)
        return LegacyQUICStream(
            id: id,
            direction: id.isUnidirectional ? .unidirectional : .bidirectional,
            connection: connection
        )
    }

    private func waitUntilReady(_ connection: NWConnection) async throws {
        let resumed = Mutex<Bool>(false)
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                    case .ready:
                        guard resumed.takeFirst() else {
                            return
                        }
                        connection.stateUpdateHandler = nil
                        continuation.resume()
                    case .failed(let error):
                        guard resumed.takeFirst() else {
                            return
                        }
                        connection.stateUpdateHandler = nil
                        continuation.resume(throwing: error)
                    default:
                        break
                }
            }
            connection.start(queue: queue)
        }
    }
}

extension Mutex where Value == Bool {
    /// Atomically flips a `false` latch to `true`, returning whether this call was the first to do so.
    // swiftlint:disable:next strict_fileprivate - needed across types in-file
    fileprivate func takeFirst() -> Bool {
        withLock { taken in
            guard !taken else {
                return false
            }
            taken = true
            return true
        }
    }
}
