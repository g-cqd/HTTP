//
//  SwiftSystemTransport.swift
//  HTTPTransport
//
//  Backbone 2c — apple/swift-system typed descriptor wrappers over the POSIX socket syscalls. Safe
//  and low-level, with compiler-typed FileDescriptor/Errno instead of raw Darwin calls.
//

/// The apple/swift-system transport backbone.
///
/// - Note: the swift-system socket bridge lands in a later M3 cycle; ``start()`` currently throws
///   ``TransportError/notImplemented(_:)``.
public final class SwiftSystemTransport: ServerTransport {

    /// The backbone this transport implements.
    public let backbone: TransportBackbone = .swiftSystem

    private let configuration: TransportConfiguration

    /// Creates a swift-system transport for `configuration`.
    public init(configuration: TransportConfiguration) {
        self.configuration = configuration
    }

    /// Begins accepting connections — not yet implemented, so it throws.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        _ = configuration
        throw TransportError.notImplemented(.swiftSystem)
    }

    /// Stops accepting and releases the listener.
    public func shutdown() async {}
}
