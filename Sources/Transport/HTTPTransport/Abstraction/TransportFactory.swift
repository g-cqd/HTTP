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
            case .networkFramework:
                NetworkFrameworkTransport(configuration: configuration)
            case .portableTLS:
                makePortableTLS(configuration)
            case .posixKqueue:
                POSIXKqueueTransport(configuration: configuration)
            case .posixDispatch:
                POSIXDispatchTransport(configuration: configuration)
            case .swiftSystem:
                SwiftSystemTransport(configuration: configuration)
            case .fake:
                FakeTransport()
        }
    }

    /// The portable libssl TLS backbone (ADR 0004), available only in the opt-in build.
    ///
    /// Compiled only with `HTTP_PORTABLE_TLS`; selecting ``TransportBackbone/portableTLS`` without that
    /// build is a configuration error — it traps with a clear message rather than silently degrading to
    /// another backbone.
    private static func makePortableTLS(
        _ configuration: TransportConfiguration
    ) -> any ServerTransport {
        #if canImport(CHTTPBoringSSL)
            return PortableTLSTransport(configuration: configuration)
        #else
            preconditionFailure(
                "the .portableTLS backbone requires building with HTTP_PORTABLE_TLS (ADR 0004)"
            )
        #endif
    }
}
