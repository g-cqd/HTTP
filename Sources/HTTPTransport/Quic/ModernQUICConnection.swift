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

    private let connection: Network.NetworkConnection<Network.QUIC>
    private let inbound: AsyncStream<any QUICStream>
    private let continuation: AsyncStream<any QUICStream>.Continuation
    private let inboundTask = Mutex<Task<Void, Never>?>(nil)

    init(
        connection: Network.NetworkConnection<Network.QUIC>,
        peer: TransportAddress,
        negotiatedApplicationProtocol: String?
    ) {
        self.connection = connection
        self.peer = peer
        self.negotiatedApplicationProtocol = negotiatedApplicationProtocol
        (self.inbound, self.continuation) = AsyncStream.makeStream()
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
            directionality: direction == .unidirectional ? .unidirectional : .bidirectional)
        return ModernQUICStream(stream: networkStream, onClose: {})
    }

    func close(errorCode: UInt64) async {
        // The modern API has no per-connection cancel; cancelling the inbound task unwinds
        // `inboundStreams` (structured concurrency), which tears the QUIC connection down.
        inboundTask.withLock { $0 }?.cancel()
    }

    /// Drives `inboundStreams`, parking each handler on a continuation the wrapped stream resumes when
    /// the engine finishes with it (so Network does not tear the stream down early).
    private func runInbound() async {
        try? await connection.inboundStreams { networkStream in
            await withCheckedContinuation { (resume: CheckedContinuation<Void, Never>) in
                self.continuation.yield(
                    ModernQUICStream(stream: networkStream, onClose: { resume.resume() }))
            }
        }
        continuation.finish()
    }
}
