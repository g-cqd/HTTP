//
//  HTTPConnectionPool.swift
//  HTTPClient
//
//  Per-origin HTTP/1.1 keep-alive pool: at most `maxConnectionsPerHost` connections (idle + leased)
//  per origin, further leases wait FIFO; idle connections are reused LIFO (warmest first) and
//  expire after `idleTimeout`.
//

internal import HTTPTLS

/// Per-origin keep-alive connection pool with a per-origin connection ceiling.
actor HTTPConnectionPool {
    private struct IdleEntry {
        let connection: HTTPClientConnection
        let since: ContinuousClock.Instant
    }

    private struct OriginState {
        var idle: [IdleEntry] = []
        var leased = 0
        var waiters: [CheckedContinuation<Void, Never>] = []
    }

    private let configuration: HTTPClientConfiguration
    private var origins: [HTTPOrigin: OriginState] = [:]
    private var anchors: TLSTrustAnchors?
    private var anchorsLoaded = false
    private var isShutDown = false

    init(configuration: HTTPClientConfiguration) {
        self.configuration = configuration
        self.anchors = configuration.trustAnchors
        self.anchorsLoaded = configuration.trustAnchors != nil
    }

    /// Leases a connection to `origin`: a warm idle one when available (`fresh == false`), else a new
    /// dial once the origin is under its ceiling.
    func lease(_ origin: HTTPOrigin) async throws -> (HTTPClientConnection, fresh: Bool) {
        guard !isShutDown else {
            throw HTTPClientError.connectionClosed
        }
        let ceiling = max(1, configuration.maxConnectionsPerHost)
        while true {
            // No suspension between reading and writing `origins[origin]`: the actor may interleave
            // other leases/releases at any await, so state is never carried across one.
            let now = ContinuousClock.now
            var expired: [HTTPClientConnection] = []
            var reused: HTTPClientConnection?
            var state = origins[origin, default: OriginState()]
            while reused == nil, let entry = state.idle.popLast() {
                if now - entry.since < configuration.idleTimeout {
                    reused = entry.connection
                }
                else {
                    expired.append(entry.connection)
                }
            }
            let canDial = reused == nil && state.leased < ceiling
            if reused != nil || canDial {
                state.leased += 1
            }
            origins[origin] = state
            for connection in expired {
                Task { await connection.close() }
            }
            if let reused {
                return (reused, false)
            }
            if canDial {
                break
            }
            await withCheckedContinuation { continuation in
                origins[origin, default: OriginState()].waiters.append(continuation)
            }
            try Task.checkCancellation()
            guard !isShutDown else {
                throw HTTPClientError.connectionClosed
            }
        }
        do {
            let connection = try await HTTPClientConnection.open(
                origin: origin,
                anchors: trustAnchors()
            )
            return (connection, true)
        }
        catch {
            releaseSlot(origin)
            throw error
        }
    }

    /// Returns `connection`: kept idle when reusable and under the idle cap, else closed.
    func release(_ connection: HTTPClientConnection) async {
        let origin = connection.origin
        let reusable = await connection.isReusable
        if reusable, !isShutDown,
            origins[origin, default: OriginState()].idle.count
                < configuration.maxIdleConnectionsPerHost
        {
            origins[origin, default: OriginState()].idle
                .append(
                    IdleEntry(connection: connection, since: ContinuousClock.now)
                )
        }
        else {
            Task { await connection.close() }
        }
        releaseSlot(origin)
    }

    /// Closes every idle connection and refuses further leases.
    func shutdown() async {
        isShutDown = true
        let idle = origins.values.flatMap(\.idle).map(\.connection)
        let waiters = origins.values.flatMap(\.waiters)
        origins.removeAll()
        for waiter in waiters { waiter.resume() }
        for connection in idle { await connection.close() }
    }

    private func releaseSlot(_ origin: HTTPOrigin) {
        guard var state = origins[origin] else {
            return
        }
        state.leased = max(0, state.leased - 1)
        if !state.waiters.isEmpty {
            state.waiters.removeFirst().resume()
        }
        origins[origin] = state
    }

    private func trustAnchors() -> TLSTrustAnchors? {
        if !anchorsLoaded {
            anchors = TLSTrustAnchors.systemBundle()
            anchorsLoaded = true
        }
        return anchors
    }
}
