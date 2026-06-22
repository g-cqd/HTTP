//
//  ModernQUICStream.swift
//  HTTPTransport
//
//  The modern (macOS 26+) QUIC stream: a `QUIC.Stream` from the typed-channel Network API, bridged to
//  async `receive`/`send`. QUIC's end-of-stream is `message.metadata.endOfStream` on a receive —
//  surfaced as `fin` for the HTTP/3 engine (RFC 9114 §4 / §7.1) — and sent as `endOfStream: true`
//  (RFC 9000 §2). An `onClose` hook lets the owning `inboundStreams` handler return once the engine is
//  done with the stream (ARC-driven: it fires on reset or when the last reference is dropped).
//

internal import Foundation
internal import HTTPCore
internal import Network
internal import Synchronization

/// A ``QUICStream`` backed by a modern Network `QUIC.Stream` (macOS 26+ backbone).
@available(macOS 26, iOS 26, *)
final class ModernQUICStream: QUICStream, @unchecked Sendable {

    let id: QUICStreamID
    let direction: QUICStreamDirection
    private let stream: Network.QUIC.Stream<Network.QUICStream>
    /// Set once the peer's FIN has been surfaced, so a later ``receive()`` reports end-of-stream.
    private let finished = Mutex<Bool>(false)
    /// Resumes the owning `inboundStreams` handler so it returns and the stream closes (call-once).
    private let onClose: Mutex<(@Sendable () -> Void)?>

    init(
        stream: Network.QUIC.Stream<Network.QUICStream>,
        onClose: @escaping @Sendable () -> Void
    ) {
        self.stream = stream
        self.id = QUICStreamID(stream.streamID)
        self.direction = stream.directionality == .unidirectional ? .unidirectional : .bidirectional
        self.onClose = Mutex(onClose)
    }

    deinit { close() }

    func receive() async throws -> (bytes: [UInt8], fin: Bool)? {
        if finished.withLock({ $0 }) { return nil }
        let message = try await stream.receive(atLeast: 1, atMost: 65_535)
        let fin = message.metadata.endOfStream
        if fin { finished.withLock { $0 = true } }
        return ([UInt8](message.content), fin)
    }

    func send(_ bytes: [UInt8], fin: Bool) async throws {
        try await stream.send(Data(bytes), endOfStream: fin)
    }

    func reset(errorCode: UInt64) {
        stream.streamApplicationErrorCode = errorCode
        close()
    }

    private func close() {
        onClose.withLock { handler in
            handler?()
            handler = nil
        }
    }
}
