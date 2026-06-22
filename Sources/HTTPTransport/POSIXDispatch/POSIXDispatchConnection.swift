//
//  POSIXDispatchConnection.swift
//  HTTPTransport
//
//  A TransportConnection driven by GCD's DispatchIO channel over a non-blocking socket. DispatchIO
//  handles read/write readiness and backpressure internally (kqueue under the hood), so there is no
//  hand-rolled event loop; callbacks are bridged to async via a once-only resumer.
//
//  Standards: the byte stream is TCP (RFC 9293) over IPv4 (RFC 791); read/write semantics follow
//  POSIX.1-2017 (IEEE Std 1003.1-2017).
//

internal import Dispatch
internal import Synchronization

/// A ``TransportConnection`` backed by a GCD `DispatchIO` channel.
///
/// `DispatchIO` and the `Atomic` close flag are thread-safe and there is no other mutable state, so
/// the type is `Sendable`. Task cancellation closes the channel to unblock a pending read.
public final class POSIXDispatchConnection: TransportConnection {

    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    private let channel: DispatchIO
    private let queue: DispatchQueue
    private let isClosed = Atomic<Bool>(false)

    /// Wraps a `DispatchIO` channel over an accepted, non-blocking socket.
    init(
        id: TransportConnectionID, channel: DispatchIO, peer: TransportAddress, queue: DispatchQueue
    ) {
        self.id = id
        self.peer = peer
        self.channel = channel
        self.queue = queue
    }

    /// Reads up to `maxLength` bytes, or `nil` at end of stream.
    ///
    /// Cancellation closes the channel to unblock a stalled read.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let channel = self.channel
        let queue = self.queue
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = OnceResumer(continuation)
                channel.read(offset: 0, length: max(1, maxLength), queue: queue) {
                    done, data, error in
                    if error != 0 {
                        once.resume(throwing: TransportError.ioFailed("read errno \(error)"))
                    } else if let data, !data.isEmpty {
                        once.resume(returning: Array(data))
                    } else if done {
                        once.resume(returning: nil)  // EOF
                    }
                }
            }
        } onCancel: {
            closeChannel()
        }
    }

    /// Writes all of `bytes`; `DispatchIO` handles short writes and backpressure internally.
    public func send(_ bytes: [UInt8]) async throws {
        let channel = self.channel
        let queue = self.queue
        let payload = bytes.withUnsafeBytes { DispatchData(bytes: $0) }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                let once = OnceResumer(continuation)
                channel.write(offset: 0, data: payload, queue: queue) { done, _, error in
                    if error != 0 {
                        once.resume(throwing: TransportError.ioFailed("write errno \(error)"))
                    } else if done {
                        once.resume(returning: ())
                    }
                }
            }
        } onCancel: {
            closeChannel()
        }
    }

    /// Closes the channel idempotently, after which its cleanup handler closes the descriptor.
    public func close() async {
        closeChannel()
    }

    private func closeChannel() {
        guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else { return }
        channel.close(flags: .stop)
    }
}
