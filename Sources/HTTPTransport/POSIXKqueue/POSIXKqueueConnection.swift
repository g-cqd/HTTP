//
//  POSIXKqueueConnection.swift
//  HTTPTransport
//
//  A TransportConnection driven entirely by a hand-rolled kqueue event loop over a non-blocking
//  socket: reads wait for EVFILT_READ then read() what is available; writes loop until drained,
//  re-arming on EVFILT_WRITE whenever the socket buffer fills. The write re-arm is event-driven
//  (each step runs on a fresh kqueue callback) — it is NOT stack recursion, so hostile peers cannot
//  grow the stack.
//
//  Standards: read()/write()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP (RFC 9293) over
//  IPv4 (RFC 791). Readiness via BSD kqueue.
//

internal import Darwin
internal import Synchronization

/// A ``TransportConnection`` whose readiness is multiplexed by a ``KqueueEventLoop``.
///
/// The descriptor and `Atomic` close flag are the only state; close is idempotent and serialized on
/// the event loop. Task cancellation closes the descriptor to unblock a pending read.
public final class POSIXKqueueConnection: TransportConnection {

    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    private let descriptor: Int32
    private let eventLoop: KqueueEventLoop
    private let isClosed = Atomic<Bool>(false)

    private enum WriteOutcome {
        case done
        case wouldBlock(offset: Int)
        case failed(errno: Int32)
    }

    /// Wraps an accepted, non-blocking socket descriptor watched by `eventLoop`.
    init(
        id: TransportConnectionID, descriptor: Int32, peer: TransportAddress,
        eventLoop: KqueueEventLoop
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.eventLoop = eventLoop
    }

    /// Reads up to `maxLength` bytes once the socket is readable, or `nil` at end of stream.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let descriptor = self.descriptor
        let eventLoop = self.eventLoop
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let once = OnceResumer(continuation)
                eventLoop.waitReadable(descriptor) {
                    Self.readAvailable(descriptor: descriptor, maxLength: maxLength, into: once)
                }
            }
        } onCancel: {
            closeDescriptor()
        }
    }

    /// Writes all of `bytes`, re-arming on writability whenever the socket buffer is full.
    public func send(_ bytes: [UInt8]) async throws {
        let descriptor = self.descriptor
        let eventLoop = self.eventLoop
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                let once = OnceResumer(continuation)
                Self.writeRemaining(
                    bytes: bytes, offset: 0, descriptor: descriptor, eventLoop: eventLoop,
                    once: once)
            }
        } onCancel: {
            closeDescriptor()
        }
    }

    /// Closes the descriptor (idempotent, serialized on the event loop to avoid an fd-reuse race).
    public func close() async {
        closeDescriptor()
    }

    private func closeDescriptor() {
        guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else { return }
        eventLoop.closeDescriptor(descriptor)
    }

    private static func readAvailable(
        descriptor: Int32, maxLength: Int, into once: OnceResumer<[UInt8]?>
    ) {
        do {
            let bytes = try POSIXSocket.readBuffer(maxLength: maxLength) { raw in
                let count = read(descriptor, raw.baseAddress, raw.count)
                guard count >= 0 else { throw TransportError.ioFailed("read errno \(errno)") }
                return count
            }
            once.resume(returning: bytes)  // nil == EOF (a zero-length read)
        } catch {
            once.resume(throwing: error)
        }
    }

    private static func writeRemaining(
        bytes: [UInt8], offset: Int, descriptor: Int32, eventLoop: KqueueEventLoop,
        once: OnceResumer<Void>
    ) {
        var offset = offset
        let outcome: WriteOutcome = bytes.withUnsafeBytes { raw in
            while offset < raw.count {
                let written = write(
                    descriptor, raw.baseAddress?.advanced(by: offset), raw.count - offset)
                if written > 0 {
                    offset += written
                } else if written < 0, errno == EWOULDBLOCK || errno == EAGAIN {
                    return .wouldBlock(offset: offset)
                } else {
                    return .failed(errno: errno)
                }
            }
            return .done
        }
        switch outcome {
        case .done:
            once.resume(returning: ())
        case .failed(let code):
            once.resume(throwing: TransportError.ioFailed("write errno \(code)"))
        case .wouldBlock(let remaining):
            eventLoop.waitWritable(descriptor) {
                writeRemaining(
                    bytes: bytes, offset: remaining, descriptor: descriptor, eventLoop: eventLoop,
                    once: once)
            }
        }
    }
}
