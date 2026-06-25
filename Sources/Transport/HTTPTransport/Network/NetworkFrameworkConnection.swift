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

    private let connection: NWConnection

    /// Wraps a connection that has reached `.ready`, recording its negotiated ALPN protocol.
    init(
        id: TransportConnectionID,
        connection: NWConnection,
        negotiatedApplicationProtocol: String?,
        isSecure: Bool
    ) {
        self.id = id
        self.peer = Self.address(of: connection.endpoint)
        self.negotiatedApplicationProtocol = negotiatedApplicationProtocol
        self.isSecure = isSecure
        self.connection = connection
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Receives up to `maxLength` inbound bytes, or `nil` once the peer half-closes (EOF).
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
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
            cancelUnderlying()
        }
    }

    /// Sends `bytes` to the peer, completing once Network.framework has accepted them.
    public func send(_ bytes: [UInt8]) async throws {
        try await withTaskCancellationHandler {
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
        } onCancel: {
            cancelUnderlying()
        }
    }

    /// Cancels the underlying connection.
    public func close() async {
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
