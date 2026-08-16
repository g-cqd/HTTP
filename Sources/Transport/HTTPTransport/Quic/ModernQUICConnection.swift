//
//  ModernQUICConnection.swift
//  HTTPTransport
//
//  The modern (macOS 26+) QUIC connection: a `NetworkConnection<QUIC>` from the typed-channel Network
//  API (RFC 9000). Inbound peer streams arrive through the structured-concurrency `inboundStreams`
//  handler; this bridges them to the ``QUICConnection/inboundStreams()`` `AsyncStream` (each handler
//  invocation parks until the engine drops its stream, so Network keeps the stream open meanwhile). The
//  server opens its own control + QPACK streams with `openStream(directionality:)` (RFC 9114 §6.2).
//  The modern types have no `cancel()`; teardown is structured — closing cancels the inbound task,
//  which unwinds `inboundStreams` and tears the connection down.
//

internal import Network
internal import Synchronization

/// A ``QUICConnection`` backed by a modern `NetworkConnection<QUIC>` (macOS 26+ backbone).
@available(macOS 26, iOS 26, *)
final class ModernQUICConnection: QUICConnection, @unchecked Sendable {
    let peer: TransportAddress
    let negotiatedApplicationProtocol: String?

    /// The admission slot charged for this connection at accept time (audit F8).
    ///
    /// Surfaced so the server adopts it rather than charging a second slot for the same peer; the
    /// listener handler's own `defer` release remains the backstop (audit addendum P0.5).
    let admissionTicket: AdmissionTicket?

    private let connection: Network.NetworkConnection<Network.QUIC>
    private let inbound: AsyncStream<any QUICStream>
    private let continuation: AsyncStream<any QUICStream>.Continuation
    private let inboundTask = Mutex<Task<Void, Never>?>(nil)

    init(
        connection: Network.NetworkConnection<Network.QUIC>,
        peer: TransportAddress,
        negotiatedApplicationProtocol: String?,
        admissionTicket: AdmissionTicket? = nil
    ) {
        self.connection = connection
        self.peer = peer
        self.negotiatedApplicationProtocol = negotiatedApplicationProtocol
        self.admissionTicket = admissionTicket
        (self.inbound, self.continuation) = AsyncStream.makeStream()
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Serves the connection for its lifetime, feeding inbound peer streams into the AsyncStream.
    ///
    /// Blocks until the connection closes (peer-driven) or ``close(errorCode:)`` cancels the inbound
    /// task.
    func serve() async {
        let task = Task { await self.runInbound() }
        inboundTask.withLock { $0 = task }
        await task.value
    }

    func inboundStreams() -> AsyncStream<any QUICStream> {
        inbound
    }

    func openStream(direction: QUICStreamDirection) async throws -> any QUICStream {
        let networkStream = try await connection.openStream(
            directionality: direction == .unidirectional ? .unidirectional : .bidirectional
        )
        return ModernQUICStream(stream: networkStream) {
            // no-op: a locally-opened stream has no close hook
        }
    }

    /// Closes the whole connection (RFC 9000 §10.2), recording the RFC 9114 §8.1 application error
    /// code in the connection's QUIC state before teardown.
    ///
    /// Best-effort by platform constraint, not by choice: the `applicationError` setter writes the
    /// code into live, shared QUIC state (a fresh metadata copy reads it back), but the structured
    /// teardown below — the modern API's only close — emits CONNECTION_CLOSE frame type 0x1d
    /// (§19.19) with a **hardwired code 0**, whatever was set. Measured, with the wire observed by a
    /// second Network.framework client; the probe is `closeCarriesTheApplicationErrorCode` in
    /// `ModernQUICTransportTests`, and the full experiment matrix is in
    /// docs/standards/CONFORMANCE.md. The write stays so the day Apple's stack consults it, the
    /// pinned probe flags the change and the wire gets the mandated code.
    ///
    /// The reason string must be **non-nil**: with `nil`, `nw_quic_set_application_error` crashes in
    /// `strlen(NULL)` (measured on macOS 27.0 — the crash that a previous attempt misread as "the
    /// connection stops closing"). It stays empty because RFC 9000 §10.2.3 cautions that reason
    /// phrases can disclose internal state.
    func close(errorCode: UInt64) async {
        connection.applicationError = .init(code: errorCode, reason: "")
        // The modern API has no per-connection cancel; cancelling the inbound task unwinds
        // `inboundStreams` (structured concurrency), which tears the QUIC connection down.
        inboundTask.withLock(\.self)?.cancel()
    }

    /// Drives `inboundStreams`, parking each handler on a continuation the wrapped stream resumes when
    /// the engine finishes with it (so Network does not tear the stream down early).
    private func runInbound() async {
        try? await connection.inboundStreams { networkStream in
            await withCheckedContinuation { (resume: CheckedContinuation<Void, Never>) in
                self.continuation.yield(
                    ModernQUICStream(stream: networkStream) { resume.resume() }
                )
            }
        }
        continuation.finish()
    }
}
