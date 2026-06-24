//
//  ModernQUICTransport.swift
//  HTTPTransport
//
//  Modern QUIC backbone (macOS 26+): the typed-channel Network API — `NetworkListener<QUIC>` +
//  `run` + `NetworkConnection<QUIC>.inboundStreams`. QUIC is configured with the builder `QUIC(alpn:)`
//  + `.tls.localIdentity(_:)` (the dev/identity TLS, RFC 9001) and the per-peer stream limits. The
//  handler-based `run` (which blocks for the listener's lifetime) is bridged to the
//  ``QUICServerTransport`` `AsyncStream`; each connection handler parks on the connection's inbound
//  loop so Network keeps it alive while the server drives it.
//
//  Standards: QUIC (RFC 9000) over UDP (RFC 768); QUIC-TLS (RFC 9001) with TLS 1.3 (RFC 8446); ALPN
//  (RFC 7301) selects "h3" for HTTP/3 (RFC 9114 §3.1). Gated to macOS 26+ via ``QUICTransportFactory``.
//

public import HTTPCore
internal import Network
internal import Synchronization

/// The modern Network.framework QUIC server backbone (`NetworkListener<QUIC>`, macOS 26+).
@available(macOS 26, iOS 26, *)
public final class ModernQUICTransport: QUICServerTransport {
    private let configuration: TransportConfiguration
    private let limits: HTTPLimits
    private let listenerBox = Mutex<Network.NetworkListener<Network.QUIC>?>(nil)
    private let runTask = Mutex<Task<Void, Never>?>(nil)

    /// Creates a modern QUIC transport for `configuration` (which must carry TLS) and `limits`.
    public init(configuration: TransportConfiguration, limits: HTTPLimits = .default) {
        self.configuration = configuration
        self.limits = limits
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// The actual bound UDP port (valid once the listener binds during ``start()``).
    public var boundPort: UInt16 {
        listenerBox.withLock { $0?.port?.rawValue ?? 0 }
    }

    /// Binds the QUIC listener and begins accepting, returning a stream of inbound connections.
    public func start() async throws -> AsyncStream<any QUICConnection> {
        guard let tls = configuration.tls else {
            throw TransportError.tlsConfigurationFailed("QUIC requires a TLS identity")
        }
        let identity = try NetworkFrameworkTLS.identity(
            pkcs12: tls.pkcs12,
            passphrase: tls.passphrase
        )
        let alpn = tls.applicationProtocols
        let maxBidirectional = limits.maxConcurrentStreams
        let listener = try Network.NetworkListener {
            Network.QUIC(alpn: alpn)
                .tls.localIdentity(identity)
                .initialMaxBidirectionalStreams(maxBidirectional)
                .initialMaxUnidirectionalStreams(16)
        }
        listenerBox.withLock { $0 = listener }

        let (stream, continuation) = AsyncStream<any QUICConnection>.makeStream()
        let host = configuration.host
        let advertised = alpn.first
        let port = boundPort
        let task = Task {
            try? await listener.run { networkConnection in
                let connection = ModernQUICConnection(
                    connection: networkConnection,
                    peer: TransportAddress(host: host, port: port),
                    negotiatedApplicationProtocol: advertised
                )
                continuation.yield(connection)
                await connection.serve()  // blocks until the connection closes
            }
            continuation.finish()
        }
        runTask.withLock { $0 = task }
        await waitUntilBound()
        return stream
    }

    /// Stops accepting: cancels the listener's run task, which unwinds it (the modern API has no
    /// `cancel()`; teardown is via structured task cancellation).
    public func shutdown() async {
        runTask.withLock(\.self)?.cancel()
    }

    /// Polls until the listener has bound its port (so ``boundPort`` is valid before returning).
    private func waitUntilBound() async {
        for _ in 0 ..< 1_000 where boundPort == 0 {
            try? await Task.sleep(for: .milliseconds(5))
        }
    }
}
