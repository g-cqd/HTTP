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
                makeNetworkFramework(configuration)
            case .portableTLS:
                makePortableTLS(configuration)
            case .posixKqueue:
                makePOSIXKqueue(configuration)
            case .posixEpoll:
                makePOSIXEpoll(configuration)
            case .posixDispatch:
                makePOSIXDispatch(configuration)
            case .swiftSystem:
                makeSwiftSystem(configuration)
            case .fake:
                FakeTransport()
        }
    }

    /// The Network.framework backbone (the only h3/QUIC path) — available only on Apple platforms.
    ///
    /// Excluded from the Linux build graph (no Network.framework); selecting it off Apple platforms is a
    /// configuration error — it traps with a clear message rather than silently degrading.
    private static func makeNetworkFramework(
        _ configuration: TransportConfiguration
    ) -> any ServerTransport {
        #if canImport(Network)
            return NetworkFrameworkTransport(configuration: configuration)
        #else
            preconditionFailure("the .networkFramework backbone requires Apple's Network.framework")
        #endif
    }

    /// The BSD-sockets + `kqueue(2)` backbone — available only on Darwin (Linux uses `.posixEpoll`).
    ///
    /// Excluded from the Linux build graph; selecting it off Darwin is a configuration error — it traps
    /// with a clear message rather than silently degrading to another backbone.
    private static func makePOSIXKqueue(
        _ configuration: TransportConfiguration
    ) -> any ServerTransport {
        #if canImport(Darwin)
            return POSIXKqueueTransport(configuration: configuration)
        #else
            preconditionFailure("the .posixKqueue backbone is Darwin-only (Linux uses .posixEpoll)")
        #endif
    }

    /// The BSD-sockets + Dispatch-sources backbone — available only on Darwin (Linux uses `.posixEpoll`).
    ///
    /// Excluded from the Linux build graph; selecting it off Darwin is a configuration error — it traps
    /// with a clear message rather than silently degrading to another backbone.
    private static func makePOSIXDispatch(
        _ configuration: TransportConfiguration
    ) -> any ServerTransport {
        #if canImport(Darwin)
            return POSIXDispatchTransport(configuration: configuration)
        #else
            preconditionFailure("the .posixDispatch backbone is Darwin-only (use .posixEpoll)")
        #endif
    }

    /// The swift-system file-descriptor backbone — available only on Darwin (Linux uses `.posixEpoll`).
    ///
    /// Excluded from the Linux build graph; selecting it off Darwin is a configuration error — it traps
    /// with a clear message rather than silently degrading to another backbone.
    private static func makeSwiftSystem(
        _ configuration: TransportConfiguration
    ) -> any ServerTransport {
        #if canImport(Darwin)
            return SwiftSystemTransport(configuration: configuration)
        #else
            preconditionFailure("the .swiftSystem backbone is Darwin-only (Linux uses .posixEpoll)")
        #endif
    }

    /// The portable libssl TLS backbone (ADR 0004), available only in the opt-in build.
    ///
    /// Compiled only with `HTTP_PORTABLE_TLS`; selecting ``TransportBackbone/portableTLS`` without that
    /// build is a configuration error — it traps with a clear message rather than silently degrading to
    /// another backbone.
    private static func makePortableTLS(
        _ configuration: TransportConfiguration
    ) -> any ServerTransport {
        #if canImport(CHTTPBoringSSLShims)
            return PortableTLSTransport(configuration: configuration)
        #else
            preconditionFailure(
                "the .portableTLS backbone requires building with HTTP_PORTABLE_TLS (ADR 0004)"
            )
        #endif
    }

    /// The Linux `epoll(7)` backbone (G0), available only on Linux.
    ///
    /// Compiled only where `Glibc` is importable; selecting ``TransportBackbone/posixEpoll`` off Linux
    /// is a configuration error — it traps with a clear message rather than silently degrading.
    /// Verified on Linux (Swift 6.5-dev / Ubuntu noble); see ``EpollEventLoop``.
    private static func makePOSIXEpoll(
        _ configuration: TransportConfiguration
    ) -> any ServerTransport {
        #if canImport(Glibc)
            return POSIXEpollTransport(configuration: configuration)
        #else
            preconditionFailure("the .posixEpoll backbone is Linux-only (requires Glibc)")
        #endif
    }
}
