//
//  POSIXKqueueTransport.swift
//  HTTPTransport
//
//  Backbone 2a — BSD sockets with a hand-rolled kqueue readiness loop. The closest-to-the-hardware
//  option: socket()/bind()/listen()/accept() with kevent()-driven readiness, bridged to async.
//

/// The BSD-sockets + kqueue transport backbone (closest to the hardware).
///
/// - Note: the kqueue event loop lands in a later M3 cycle; ``start()`` currently throws
///   ``TransportError/notImplemented(_:)``.
public final class POSIXKqueueTransport: ServerTransport {

    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .posixKqueue

    private let configuration: TransportConfiguration

    /// Creates a BSD-sockets + kqueue transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// Begins accepting connections — not yet implemented, so it throws.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        _ = configuration
        throw TransportError.notImplemented(.posixKqueue)
    }

    /// Stops accepting and releases the listener.
    public func shutdown() async {}
}
