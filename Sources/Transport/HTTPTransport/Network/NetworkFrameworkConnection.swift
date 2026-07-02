//
//  NetworkFrameworkConnection.swift
//  HTTPTransport
//
//  Bridges a Network.framework NWConnection to the TransportConnection abstraction — callback-based
//  send/receive become async via continuations.
//

internal import Foundation
internal import Network

/// A ``TransportConnection`` backed by a Network.framework `NWConnection`.
///
/// `NWConnection`'s `send`, `receive`, and `cancel` are documented thread-safe, and this wrapper
/// adds no mutable Swift state of its own, so it is safe to share across tasks — hence
/// `@unchecked Sendable`. The connection's callback I/O is bridged to `async` with continuations.
public final class NetworkFrameworkConnection: TransportConnection, @unchecked Sendable {
    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    /// The ALPN-negotiated protocol (RFC 7301), captured once the handshake reached `.ready`.
    public let negotiatedApplicationProtocol: String?

    /// Whether this connection arrived over TLS (so ALPN was advertised and is enforced).
    public let isSecure: Bool

    /// The verified client-certificate subject (mutual TLS), captured at `.ready`, or `nil` when no
    /// client certificate was presented.
    public let tlsPeerSubject: String?

    private let connection: NWConnection

    /// Wraps a connection that has reached `.ready`, recording its negotiated ALPN protocol and, for
    /// mutual TLS, the verified client-certificate subject.
    init(
        id: TransportConnectionID,
        connection: NWConnection,
        negotiatedApplicationProtocol: String?,
        isSecure: Bool,
        tlsPeerSubject: String? = nil
    ) {
        self.id = id
        self.peer = Self.address(of: connection.endpoint)
        self.negotiatedApplicationProtocol = negotiatedApplicationProtocol
        self.isSecure = isSecure
        self.tlsPeerSubject = tlsPeerSubject
        self.connection = connection
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Receives up to `maxLength` inbound bytes, or `nil` once the peer half-closes (EOF).
    ///
    /// Honors per-call task cancellation (the ``TransportConnection`` receive contract): a per-read
    /// handler cancels the `NWConnection`, which fires this receive's completion with an error, and
    /// the lapse surfaces as `CancellationError`. Every receive on this backbone rides a framework
    /// callback anyway, so — unlike the loop-pinned backbones (audit CC4) — there is no handler-free
    /// hot path to preserve.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let bytes: [UInt8]?
        do {
            bytes = try await withTaskCancellationHandler {
                try await withUnsafeThrowingContinuation { continuation in
                    connection.receive(
                        minimumIncompleteLength: 1,
                        maximumLength: max(1, maxLength)
                    ) { data, _, isComplete, error in
                        if let error {
                            continuation.resume(throwing: error)
                        }
                        else if let data, !data.isEmpty {
                            continuation.resume(returning: [UInt8](data))
                        }
                        else if isComplete {
                            continuation.resume(returning: nil)  // peer half-closed
                        }
                        else {
                            continuation.resume(returning: [])
                        }
                    }
                }
            } onCancel: {
                self.cancelUnderlying()
            }
        }
        catch _ where Task.isCancelled {
            // The receive failed because this task's cancellation tore the connection down — report
            // the standard cancellation signal instead of the framework error.
            throw CancellationError()
        }
        // A cancelled `NWConnection` can also complete the pending receive as a clean end-of-stream
        // (no error); when this task's own cancellation manufactured that EOF, report the standard
        // signal rather than a fake peer half-close.
        if bytes == nil {
            try Task.checkCancellation()
        }
        return bytes
    }

    /// Receives up to `maxLength` inbound bytes, **appending** them to `buffer`, and returns the count
    /// appended (`0` at EOF).
    ///
    /// The allocation-lean read path (audit #7): Network.framework hands back its own `Data`, so this
    /// copies those bytes straight into the caller's `buffer` via `Data.withUnsafeBytes` — one copy,
    /// dropping the intermediate `[UInt8]` chunk the protocol default builds before appending it. The
    /// branch semantics mirror ``receive(maxLength:)`` (error / data / EOF / spurious empty wakeup),
    /// as does the per-call cancellation handling (the ``TransportConnection`` receive contract).
    public func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        let received: Data?
        do {
            received = try await withTaskCancellationHandler {
                try await withUnsafeThrowingContinuation {
                    (continuation: UnsafeContinuation<Data?, any Error>) in
                    connection.receive(
                        minimumIncompleteLength: 1,
                        maximumLength: max(1, maxLength)
                    ) { data, _, isComplete, error in
                        if let error {
                            continuation.resume(throwing: error)
                        }
                        else if let data, !data.isEmpty {
                            continuation.resume(returning: data)
                        }
                        else if isComplete {
                            continuation.resume(returning: nil)  // peer half-closed
                        }
                        else {
                            continuation.resume(returning: Data())
                        }
                    }
                }
            } onCancel: {
                self.cancelUnderlying()
            }
        }
        catch _ where Task.isCancelled {
            // See ``receive(maxLength:)`` — a cancel-torn receive reports the standard signal.
            throw CancellationError()
        }
        // Append the received bytes in place — no intermediate `[UInt8]`; `nil` (EOF) and an empty
        // payload both append nothing and report `0`, matching the protocol-default behaviour. A
        // cancel-manufactured EOF reports the standard signal instead (see ``receive(maxLength:)``).
        guard let received, !received.isEmpty else {
            if received == nil {
                try Task.checkCancellation()
            }
            return 0
        }
        received.withUnsafeBytes { buffer.append(contentsOf: $0) }
        return received.count
    }

    /// Sends `bytes` to the peer, completing once Network.framework has accepted them.
    public func send(_ bytes: [UInt8]) async throws {
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
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

    /// Cancels the underlying connection.
    public func close() async {
        cancelUnderlying()
    }

    /// Cancels the underlying connection synchronously to unblock a parked receive/send (audit CC4) —
    /// the server's once-per-connection cancellation handler calls this; `NWConnection.cancel()` is
    /// idempotent.
    public func cancel() {
        cancelUnderlying()
    }

    private func cancelUnderlying() {
        connection.cancel()
    }

    private static func address(of endpoint: NWEndpoint) -> TransportAddress {
        if case .hostPort(let host, let port) = endpoint {
            return TransportAddress(host: "\(host)", port: port.rawValue)
        }
        return TransportAddress(host: "\(endpoint)", port: 0)
    }
}
