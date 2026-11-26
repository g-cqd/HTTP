//
//  HTTPClientConnection.swift
//  HTTPClient
//
//  One outbound HTTP/1.1 connection: a ``TransportConnection`` from ``TCPClientConnector``, optionally
//  wrapped in the sans-I/O ``TLSClientConnection`` (TLS 1.3, ALPN `http/1.1`). Carries one exchange
//  at a time (the pool guarantees exclusivity); `plaintext` buffers decrypted octets read past the
//  current message so a pipelined tail is never lost.
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTLS
internal import HTTPTLSRSA
internal import HTTPTransport

/// One outbound HTTP/1.1 connection, used by one exchange at a time.
actor HTTPClientConnection {
    let origin: HTTPOrigin
    private let transport: any TransportConnection
    private var tls: TLSClientConnection?
    /// Decrypted (or cleartext) inbound octets not yet consumed by the message parser.
    private(set) var plaintext: [UInt8] = []
    /// The peer sent EOF / `close_notify`.
    private(set) var reachedEOF = false
    /// Whether this connection may carry another exchange.
    var isReusable = true
    /// Exchanges completed on this connection (0 for a fresh dial).
    var completedExchanges = 0

    private static let readChunk = 64 * 1_024

    private init(origin: HTTPOrigin, transport: any TransportConnection, tls: TLSClientConnection?)
    {
        self.origin = origin
        self.transport = transport
        self.tls = tls
    }

    /// Dials `origin` and, for `https`, completes the TLS 1.3 handshake (SNI + certificate + SAN check).
    static func open(
        origin: HTTPOrigin, anchors: TLSTrustAnchors?
    ) async throws -> HTTPClientConnection {
        let transport: any TransportConnection
        do {
            transport = try await TCPClientConnector.connect(host: origin.host, port: origin.port)
        }
        catch let error as CancellationError {
            throw error
        }
        catch {
            throw HTTPClientError.connectFailed("\(origin): \(error)")
        }
        guard origin.isSecure else {
            return HTTPClientConnection(origin: origin, transport: transport, tls: nil)
        }
        guard let anchors else {
            await transport.close()
            throw HTTPClientError.tlsFailed("no trust anchors available")
        }
        var configuration = TLSClientConfiguration(serverName: origin.host, trustRootsDER: [])
        configuration.alpnProtocols = ["http/1.1"]
        configuration.certificateVerifier = TLSRSACertificateVerifier()
        let connection = HTTPClientConnection(
            origin: origin,
            transport: transport,
            tls: TLSClientConnection(configuration: configuration, anchors: anchors)
        )
        do {
            try await connection.handshake()
        }
        catch {
            await connection.close()
            throw error
        }
        return connection
    }

    private func handshake() async throws {
        guard var session = tls else {
            return
        }
        tls = nil
        defer { tls = session }
        do {
            try session.start()
            try await transport.send(session.outboundBytes())
            var completed = false
            while !completed {
                guard let bytes = try await transport.receive(maxLength: Self.readChunk) else {
                    throw HTTPClientError.tlsFailed("connection closed during handshake")
                }
                for event in try await session.receive(bytes) {
                    switch event {
                        case .handshakeCompleted:
                            completed = true
                        case .applicationData(let data):
                            plaintext.append(contentsOf: data)
                        case .peerClosed:
                            reachedEOF = true
                    }
                }
                let flight = session.outboundBytes()
                if !flight.isEmpty {
                    try await transport.send(flight)
                }
            }
        }
        catch let error as TLSHandshakeError {
            throw HTTPClientError.tlsFailed("\(origin.host): \(error)")
        }
    }

    /// Sends `bytes` (encrypting them on TLS connections).
    func write(_ bytes: [UInt8]) async throws {
        do {
            if var session = tls {
                try session.send(applicationData: bytes)
                tls = session
                try await transport.send(session.outboundBytes())
                tls = session
            }
            else {
                try await transport.send(bytes)
            }
        }
        catch {
            isReusable = false
            throw HTTPClientError.connectionClosed
        }
    }

    /// Reads at least one more octet into ``plaintext``; returns `false` at EOF.
    func readMore() async throws -> Bool {
        while !reachedEOF {
            let received: [UInt8]?
            do {
                received = try await transport.receive(maxLength: Self.readChunk)
            }
            catch let error as CancellationError {
                throw error
            }
            catch {
                isReusable = false
                throw HTTPClientError.connectionClosed
            }
            guard let bytes = received else {
                reachedEOF = true
                break
            }
            guard var session = tls else {
                plaintext.append(contentsOf: bytes)
                return true
            }
            tls = nil
            let before = plaintext.count
            do {
                for event in try await session.receive(bytes) {
                    switch event {
                        case .applicationData(let data):
                            plaintext.append(contentsOf: data)
                        case .peerClosed:
                            reachedEOF = true
                        case .handshakeCompleted:
                            break
                    }
                }
            }
            catch {
                tls = session
                isReusable = false
                throw HTTPClientError.tlsFailed("\(origin.host): \(error)")
            }
            let flight = session.outboundBytes()  // KeyUpdate responses
            tls = session
            if !flight.isEmpty {
                try? await transport.send(flight)
            }
            if plaintext.count > before {
                return true
            }
        }
        isReusable = false
        return false
    }

    /// Drops the first `count` buffered octets (a consumed message).
    func consume(_ count: Int) {
        plaintext.removeFirst(min(count, plaintext.count))
    }

    /// Sends `close_notify` (TLS) and closes the transport.
    func close() async {
        isReusable = false
        if var session = tls {
            session.close()
            tls = session
            try? await transport.send(session.outboundBytes())
        }
        await transport.close()
    }

    /// Aborts in-flight I/O immediately (cancellation / deadline).
    nonisolated func abort() {
        transport.cancel()
    }
}
