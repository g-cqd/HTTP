//
//  TransportFactory.swift
//  HTTPTransport
//
//  Instantiates the backbone selected by a TransportConfiguration — the single switch point. A
//  backbone absent from the current build graph (platform- or flag-gated) is a configuration error
//  surfaced as a thrown ``TransportError/unsupported(_:)`` — never a trap (ADR 0002: remote or
//  configuration input must not be able to abort the process), and never a silent degrade to a
//  different backbone.
//

/// Creates the ``ServerTransport`` selected by a ``TransportConfiguration``.
public enum TransportFactory {
    /// Instantiates the backbone named by `configuration.backbone`.
    ///
    /// Throws ``TransportError/unsupported(_:)`` when the selected backbone is not in this build's
    /// graph — a platform-gated backbone off its platform, or ``TransportBackbone/portableTLS``
    /// without the `HTTP_PORTABLE_TLS` build — rather than trapping or silently degrading.
    public static func make(
        _ configuration: TransportConfiguration
    ) throws(TransportError) -> any ServerTransport {
        switch configuration.backbone {
            case .networkFramework:
                try makeNetworkFramework(configuration)
            case .portableTLS:
                try makePortableTLS(configuration)
            case .posixKqueue:
                try makePOSIXKqueue(configuration)
            case .posixEpoll:
                try makePOSIXEpoll(configuration)
            case .posixDispatch:
                try makePOSIXDispatch(configuration)
            case .swiftSystem:
                try makeSwiftSystem(configuration)
            case .fake:
                FakeTransport()
        }
    }

    /// The Network.framework backbone (the only h3/QUIC path) — available only on Apple platforms.
    ///
    /// Excluded from the Linux build graph (no Network.framework); selecting it off Apple platforms
    /// is a configuration error — thrown, not trapped.
    private static func makeNetworkFramework(
        _ configuration: TransportConfiguration
    ) throws(TransportError) -> any ServerTransport {
        #if canImport(Network)
            return NetworkFrameworkTransport(configuration: configuration)
        #else
            throw .unsupported("the .networkFramework backbone requires Apple's Network.framework")
        #endif
    }

    /// The BSD-sockets + `kqueue(2)` backbone — available only on Darwin (Linux uses `.posixEpoll`).
    ///
    /// Excluded from the Linux build graph; selecting it off Darwin is a configuration error —
    /// thrown, not trapped, and never a silent degrade to another backbone.
    private static func makePOSIXKqueue(
        _ configuration: TransportConfiguration
    ) throws(TransportError) -> any ServerTransport {
        #if canImport(Darwin)
            return POSIXKqueueTransport(configuration: configuration)
        #else
            throw .unsupported("the .posixKqueue backbone is Darwin-only (Linux uses .posixEpoll)")
        #endif
    }

    /// The BSD-sockets + Dispatch-sources backbone — available only on Darwin (Linux uses `.posixEpoll`).
    ///
    /// Excluded from the Linux build graph; selecting it off Darwin is a configuration error —
    /// thrown, not trapped, and never a silent degrade to another backbone.
    private static func makePOSIXDispatch(
        _ configuration: TransportConfiguration
    ) throws(TransportError) -> any ServerTransport {
        #if canImport(Darwin)
            return POSIXDispatchTransport(configuration: configuration)
        #else
            throw .unsupported("the .posixDispatch backbone is Darwin-only (use .posixEpoll)")
        #endif
    }

    /// The swift-system file-descriptor backbone — available only on Darwin (Linux uses `.posixEpoll`).
    ///
    /// Excluded from the Linux build graph; selecting it off Darwin is a configuration error —
    /// thrown, not trapped, and never a silent degrade to another backbone.
    private static func makeSwiftSystem(
        _ configuration: TransportConfiguration
    ) throws(TransportError) -> any ServerTransport {
        #if canImport(Darwin)
            return SwiftSystemTransport(configuration: configuration)
        #else
            throw .unsupported("the .swiftSystem backbone is Darwin-only (Linux uses .posixEpoll)")
        #endif
    }

    /// The portable libssl TLS backbone (ADR 0004), available only in the opt-in build.
    ///
    /// Compiled only with `HTTP_PORTABLE_TLS`; selecting ``TransportBackbone/portableTLS`` without
    /// that build is a configuration error — thrown, not trapped.
    private static func makePortableTLS(
        _ configuration: TransportConfiguration
    ) throws(TransportError) -> any ServerTransport {
        #if canImport(CHTTPBoringSSLShims)
            return PortableTLSTransport(configuration: configuration)
        #else
            throw .unsupported(
                "the .portableTLS backbone requires building with HTTP_PORTABLE_TLS (ADR 0004)"
            )
        #endif
    }

    /// The Linux `epoll(7)` backbone (G0), available only on Linux.
    ///
    /// Compiled only where `Glibc` is importable; selecting ``TransportBackbone/posixEpoll`` off
    /// Linux is a configuration error — thrown, not trapped. Verified on Linux (Swift 6.5-dev /
    /// Ubuntu noble); see ``EpollEventLoop``.
    private static func makePOSIXEpoll(
        _ configuration: TransportConfiguration
    ) throws(TransportError) -> any ServerTransport {
        #if canImport(Glibc)
            return POSIXEpollTransport(configuration: configuration)
        #else
            throw .unsupported("the .posixEpoll backbone is Linux-only (requires Glibc)")
        #endif
    }
}
