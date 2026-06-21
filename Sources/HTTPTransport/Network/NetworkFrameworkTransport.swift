//
//  NetworkFrameworkTransport.swift
//  HTTPTransport
//
//  Backbone 1 — Apple Network.framework (NWListener / NWConnection): TLS, ALPN, and QUIC, bridged
//  to Swift Concurrency. The async NetworkListener API is iOS 26+, so this uses the callback-based
//  NWListener/NWConnection (available at our floor) and bridges via AsyncStream/continuations.
//

/// The Network.framework transport backbone.
///
/// - Note: the listener/connection bridge lands in a later M3 cycle; ``start()`` currently throws
///   ``TransportError/notImplemented(_:)``.
public final class NetworkFrameworkTransport: ServerTransport {

    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .networkFramework

    private let configuration: TransportConfiguration

    /// Creates a Network.framework transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// Begins accepting connections — not yet implemented, so it throws.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        _ = configuration
        throw TransportError.notImplemented(.networkFramework)
    }

    /// Stops accepting and releases the listener.
    public func shutdown() async {}
}
