//
//  LegacyQUICTransport.swift
//  HTTPTransport
//
//  Legacy QUIC backbone (macOS 15 floor; no `@available`): an `NWListener` configured with
//  `NWProtocolQUIC.Options` (ALPN "h3" + the dev/identity TLS, RFC 9001). QUIC is a multiplexing
//  protocol, so the listener surfaces each connection through `newConnectionGroupHandler` as an
//  `NWConnectionGroup`, which ``LegacyQUICConnection`` wraps. The handshake setup reuses
//  ``NetworkFrameworkTLS`` for the PKCS#12 identity and TLS-version pinning.
//
//  Standards: QUIC (RFC 9000) over UDP (RFC 768); QUIC-TLS (RFC 9001) with TLS 1.3 (RFC 8446); ALPN
//  (RFC 7301) selects "h3" for HTTP/3 (RFC 9114 §3.1).
//

internal import Foundation
public import HTTPCore
internal import Network
internal import Synchronization

/// The legacy Network.framework QUIC server backbone (`NWListener` + `NWConnectionGroup`).
///
/// **Peer attribution.** Each accepted connection group is charged to, and reports, the address its
/// peer is speaking from — read from the group's descriptor members, so an h3 client counts against
/// the same per-host ceiling as an h1/h2 client from the same address. Should a group name no member,
/// the connection still serves but is attributed to ``QUICPeer/unattributed`` rather than to a guess;
/// every such connection then shares one admission bucket and one rate-limit budget (fail-closed,
/// CWE-770).
public final class LegacyQUICTransport: QUICServerTransport {
    private let configuration: TransportConfiguration
    private let limits: HTTPLimits
    private let queue = DispatchQueue(label: "http.transport.quic.legacy")
    private let state = Mutex<State>(State())

    private struct State {
        var listener: NWListener?
        var isReady = false
        var failure: TransportError?
        var readyContinuation: CheckedContinuation<Void, any Error>?
        /// The shared connection ceiling, charged before a connection group is yielded (audit F8).
        var admission: ConnectionAdmission?
    }

    /// Creates a legacy QUIC transport for `configuration` (which must carry TLS) and `limits`.
    public init(configuration: TransportConfiguration, limits: HTTPLimits = .default) {
        self.configuration = configuration
        self.limits = limits
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// The actual bound UDP port (valid after ``start()``; resolves an ephemeral `0` request).
    public var boundPort: UInt16 {
        state.withLock { $0.listener?.port?.rawValue ?? 0 }
    }

    /// Binds the QUIC listener and begins accepting, returning a stream of inbound connections.
    ///
    /// A QUIC listener has no readiness source to suspend, so the per-connection refusal *is* the
    /// backpressure (audit F8): a peer over the ceiling gets a CONNECTION_CLOSE (RFC 9000 §19.19)
    /// before any HTTP/3 stream is read. The slot is charged before the connection is yielded and is
    /// owned by the connection object, so it comes back when that connection is torn down.
    public func start(
        admission: ConnectionAdmission?
    ) async throws -> AsyncStream<any QUICConnection> {
        let listener = try makeListener()
        state.withLock { $0.admission = admission }
        let (stream, continuation) = AsyncStream<any QUICConnection>.makeStream()

        listener.newConnectionGroupHandler = { [weak self] group in
            self?.handleNewGroup(group, continuation: continuation)
        }
        listener.stateUpdateHandler = { [weak self] newState in
            self?.handleStateChange(newState, continuation: continuation)
        }
        continuation.onTermination = { [weak self] _ in
            Task { await self?.shutdown() }
        }

        state.withLock { $0.listener = listener }
        listener.start(queue: queue)
        try await waitUntilReady()
        return stream
    }

    /// Cancels the QUIC listener and stops accepting connections.
    public func shutdown() async {
        let listener: NWListener? = state.withLock {
            let current = $0.listener
            $0.listener = nil
            return current
        }
        listener?.cancel()
    }

    // MARK: - Internals

    private func makeListener() throws -> NWListener {
        guard let tls = configuration.tls else {
            throw TransportError.tlsConfigurationFailed("QUIC requires a TLS identity")
        }
        // 0-RTT early data: `NWProtocolQUIC.Options` exposes no early-data knob, and we do not enable
        // it, so no request is processed from replayable early data (RFC 9001 §9.2) — see
        // ModernQUICTransport for the full policy + the 425 Too Early (RFC 8470) defense if ever enabled.
        let options = NWProtocolQUIC.Options(alpn: tls.applicationProtocols)
        let identity = try NetworkFrameworkTLS.identity(
            pkcs12: tls.pkcs12,
            passphrase: tls.passphrase
        )
        sec_protocol_options_set_local_identity(options.securityProtocolOptions, identity)
        sec_protocol_options_set_min_tls_protocol_version(
            options.securityProtocolOptions,
            .TLSv13
        )
        sec_protocol_options_set_max_tls_protocol_version(
            options.securityProtocolOptions,
            .TLSv13
        )
        // Bound the peer's streams: request streams to the concurrency cap, and a small headroom for
        // the client's three critical unidirectional streams (control + QPACK encoder/decoder) + grease.
        options.initialMaxStreamsBidirectional = limits.maxConcurrentStreams
        options.initialMaxStreamsUnidirectional = 16
        let parameters = NWParameters(quic: options)
        let port = NWEndpoint.Port(rawValue: configuration.port) ?? .any
        do {
            return try NWListener(using: parameters, on: port)
        }
        catch {
            throw TransportError.bindFailed("\(error)")
        }
    }

    private func handleNewGroup(
        _ group: NWConnectionGroup,
        continuation: AsyncStream<any QUICConnection>.Continuation
    ) {
        // The group's descriptor names its members, and for a listener-vended multiplex group that is
        // the peer — available synchronously here, before any stream, which is where the slot must be
        // charged. (Apple documents `members` only for the client-side `NWMultiplexGroup(to:)`; the
        // inbound behaviour is verified against the SDK. `NWConnectionGroup` itself exposes no path or
        // endpoint, and the per-stream `NWConnection.endpoint` would arrive far too late.)
        let peer = QUICPeer.address(of: group.descriptor.members.first)
        // Charge before yielding, so a QUIC peer counts against the same ceiling as a TCP one and an
        // over-cap peer is refused before the server ever drives a stream on it (audit F8).
        let ticket: AdmissionTicket?
        switch state.withLock(\.admission)?.admit(host: peer.host) {
            case .rejectedTotal, .rejectedHost:
                group.cancel()  // CONNECTION_CLOSE (RFC 9000 §19.19) — the refusal
                return
            case .admitted(let charged, _):
                ticket = charged
            case nil:
                ticket = nil
        }
        // This transport offers only "h3", so a completed QUIC handshake has negotiated it.
        let connection = LegacyQUICConnection(
            group: group,
            queue: queue,
            peer: peer,
            negotiatedApplicationProtocol: configuration.tls?.applicationProtocols.first,
            admissionTicket: ticket
        )
        connection.start()
        continuation.yield(connection)
    }

    private func handleStateChange(
        _ newState: NWListener.State,
        continuation: AsyncStream<any QUICConnection>.Continuation
    ) {
        state.withLock { current in
            switch newState {
                case .ready:
                    current.isReady = true
                    current.readyContinuation?.resume()
                    current.readyContinuation = nil
                case .failed(let error):
                    let failure = TransportError.bindFailed("\(error)")
                    current.failure = failure
                    current.readyContinuation?.resume(throwing: failure)
                    current.readyContinuation = nil
                    continuation.finish()
                case .cancelled:
                    continuation.finish()
                default:
                    break
            }
        }
    }

    private func waitUntilReady() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            state.withLock { current in
                if current.isReady {
                    continuation.resume()
                }
                else if let failure = current.failure {
                    continuation.resume(throwing: failure)
                }
                else {
                    current.readyContinuation = continuation
                }
            }
        }
    }
}
