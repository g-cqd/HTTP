//
//  POSIXDispatchTransport.swift
//  HTTPTransport
//
//  Backbone 2b — BSD sockets with GCD DispatchSource readiness (kqueue under the hood, far less
//  hand-rolled event-loop code), bridged to async.
//

/// The BSD-sockets + Dispatch transport backbone.
///
/// - Note: the Dispatch readiness bridge lands in a later M3 cycle; ``start()`` currently throws
///   ``TransportError/notImplemented(_:)``.
public final class POSIXDispatchTransport: ServerTransport {

    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .posixDispatch

    private let configuration: TransportConfiguration

    /// Creates a BSD-sockets + Dispatch transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// Begins accepting connections — not yet implemented, so it throws.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        _ = configuration
        throw TransportError.notImplemented(.posixDispatch)
    }

    /// Stops accepting and releases the listener.
    public func shutdown() async {}
}
