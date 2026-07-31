//
//  HTTPServer+HTTP3Lifecycle.swift
//  HTTPServer
//
//  The QUIC connection lifecycle the HTTP/3 runtime shares with the TCP one (audit addendum P0.5):
//  admission, the in-flight registry, and the graceful drain.
//
//  Before this file, `runHTTP3` created one serve task per inbound QUIC connection with **no** count
//  consulted at the server at all, and `shutdown(within:)` walked a registry that held TCP connections
//  only — so an HTTP/3 peer neither counted against the process-wide ceiling nor could be drained or
//  force-closed. The gate itself (``ConnectionAdmission``, audit F8) already existed and the QUIC
//  transports already accepted it; what was missing was the server end of the same contract that
//  `HTTPServer.accept(_:)` implements for TCP — adopt the ticket a gated backbone charged, or charge
//  one here for an ungated backbone, and hold it for exactly the serve loop.
//
//  Standards: a resource-exhaustion defense in the spirit of RFC 9110 §15.5.30 (429) — CWE-770,
//  CWE-400 — plus RFC 9114 §5.2 (GOAWAY) and RFC 9000 §19.19 (CONNECTION_CLOSE).
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport
internal import Synchronization

extension HTTPServer {
    /// One QUIC connection being served, as the drain needs to see it.
    ///
    /// The registry holds the streams (so a forced close can reset each), and the engine is what
    /// queues the GOAWAY — routed to the control stream by the same dispatcher the serve loop uses.
    struct HTTP3Handle: Sendable {
        let quic: any QUICConnection
        let registry: HTTP3StreamRegistry
        let engine: Engine
    }

    /// Takes ownership of the admission slot charged for `quic`, serves it, then releases the slot.
    ///
    /// The QUIC peer of ``accept(_:)``. A gated backbone charged the slot before the connection was
    /// yielded — before this task existed — so the common path is pure adoption; an ungated listener
    /// (the in-memory fakes, the direct-drive tools) carries no ticket and is charged here, still
    /// before a single HTTP/3 stream is read.
    ///
    /// A connection over either ceiling is closed at once with H3_EXCESSIVE_LOAD (RFC 9114 §8.1) in a
    /// CONNECTION_CLOSE (RFC 9000 §19.19): a QUIC listener has no readiness source to suspend, so the
    /// refusal itself *is* the backpressure.
    func acceptHTTP3(_ quic: any QUICConnection) async {
        guard let ticket = quic.admissionTicket ?? chargeHTTP3(quic) else {
            await quic.close(errorCode: HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
            return
        }
        defer { ticket.release() }
        await serveHTTP3(quic)
    }

    /// Charges an admission slot for a QUIC connection its listener did not charge for, or `nil` when
    /// it is over the global or per-client ceiling.
    private func chargeHTTP3(_ quic: any QUICConnection) -> AdmissionTicket? {
        guard case .admitted(let ticket, _) = admission.admit(host: quic.peer.host) else {
            return nil
        }
        return ticket
    }

    /// Registers a QUIC connection with the shutdown registry, returning its key.
    func registerHTTP3(_ handle: HTTP3Handle) -> Int {
        let key = nextQUICHandleID.wrappingAdd(1, ordering: .relaxed).newValue
        activeQUICConnections.withLock { $0[key] = handle }
        return key
    }

    /// Drops a QUIC connection from the shutdown registry once its serve loop ends.
    func unregisterHTTP3(_ key: Int) {
        activeQUICConnections.withLock { $0[key] = nil }
    }

    /// Announces the drain on every live QUIC connection with a GOAWAY (RFC 9114 §5.2).
    ///
    /// The engine queues the frame role-addressed to the control stream and the dispatcher flushes it
    /// there, so this is safe to run concurrently with the stream tasks that are also draining
    /// `outbound()`: whichever drain picks the action up, it is routed by the id or role it names, not
    /// by whoever drained it (audit addendum P0.3).
    func drainHTTP3Connections() async {
        for handle in activeQUICConnections.withLock({ Array($0.values) }) {
            let actions = await handle.engine.beginGracefulShutdown()
            await applyHTTP3(
                actions, registry: handle.registry, engine: handle.engine, quic: handle.quic
            )
        }
    }

    /// Force-closes every QUIC connection still in flight past the shutdown deadline.
    ///
    /// Each live stream is reset first so an in-flight request stops promptly rather than waiting on
    /// the connection teardown, then the connection itself gets a CONNECTION_CLOSE carrying H3_NO_ERROR
    /// — the shutdown is orderly, not an error (RFC 9114 §8.1 / RFC 9000 §19.19).
    func forceCloseHTTP3Connections() async {
        for handle in activeQUICConnections.withLock({ Array($0.values) }) {
            for stream in handle.registry.allStreams() {
                stream.reset(errorCode: HTTP3ErrorCode.h3NoError.rawValue)
            }
            await handle.quic.close(errorCode: HTTP3ErrorCode.h3NoError.rawValue)
        }
    }

    /// The number of QUIC connections currently being served.
    var liveHTTP3ConnectionCount: Int {
        activeQUICConnections.withLock(\.count)
    }
}
