//
//  TransportFactory.swift
//  HTTPTransport
//
//  Instantiates the backbone selected by a TransportConfiguration — the single switch point.
//

/// Creates the ``ServerTransport`` selected by a ``TransportConfiguration``.
public enum TransportFactory {

    /// Instantiates the backbone named by `configuration.backbone`.
    public static func make(_ configuration: TransportConfiguration) -> any ServerTransport {
        switch configuration.backbone {
        case .networkFramework: NetworkFrameworkTransport(configuration: configuration)
        case .posixKqueue: POSIXKqueueTransport(configuration: configuration)
        case .posixDispatch: POSIXDispatchTransport(configuration: configuration)
        case .swiftSystem: SwiftSystemTransport(configuration: configuration)
        case .fake: FakeTransport()
        }
    }
}
