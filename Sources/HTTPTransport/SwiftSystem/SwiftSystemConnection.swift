//
//  SwiftSystemConnection.swift
//  HTTPTransport
//
//  A TransportConnection over an accepted socket, using apple/swift-system's typed FileDescriptor
//  for read/write/close (Errno errors). Blocking syscalls run on a per-connection *serial* queue so
//  read/write/close never overlap (closing the fd from under an in-flight syscall — and the OS
//  reusing that fd number — cannot happen).
//
//  Task cancellation must NOT close via that serial queue: a blocked read already occupies the
//  queue, so a queued close would deadlock behind it. Instead cancellation calls shutdown(2) directly
//  (thread-safe, off-queue), which wakes the stalled read/write so the queue frees and the real
//  close() then runs in order.
//
//  Standards: read()/write()/close()/shutdown() per POSIX.1-2017 (IEEE Std 1003.1-2017). The byte
//  stream is TCP (RFC 9293) over IPv4 (RFC 791).
//

internal import Darwin
internal import Dispatch
internal import Synchronization
internal import SystemPackage

/// A ``TransportConnection`` backed by a swift-system `FileDescriptor` over an accepted socket.
///
/// I/O is serialized on a per-connection queue (targeting a shared pool); an `Atomic` flag makes
/// `close` idempotent. All stored state is `Sendable`, so the type needs no `@unchecked`.
public final class SwiftSystemConnection: TransportConnection {
    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    private let descriptor: FileDescriptor
    private let ioQueue: DispatchQueue
    private let isClosed = Atomic<Bool>(false)

    /// Wraps an accepted socket `descriptor`; I/O is serialized on a queue targeting `targetQueue`.
    init(
        id: TransportConnectionID,
        descriptor: FileDescriptor,
        peer: TransportAddress,
        targetQueue: DispatchQueue
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.ioQueue = DispatchQueue(
            label: "http.transport.swift-system.conn.\(id.rawValue)", target: targetQueue)
    }

    /// Reads up to `maxLength` bytes, or `nil` at end of stream.
    ///
    /// Cancellation closes the descriptor to unblock a stalled read.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let descriptor = self.descriptor
        let queue = self.ioQueue
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    do {
                        let bytes = try POSIXSocket.readBuffer(maxLength: maxLength) {
                            try descriptor.read(into: $0)
                        }
                        continuation.resume(returning: bytes)
                    }
                    catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            shutdownDescriptor()
        }
    }

    /// Writes all of `bytes` (handling short writes), walking a `RawSpan` over the payload.
    public func send(_ bytes: [UInt8]) async throws {
        let descriptor = self.descriptor
        let queue = self.ioQueue
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                queue.async {
                    do {
                        try Self.writeAll(bytes, to: descriptor)
                        continuation.resume()
                    }
                    catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            shutdownDescriptor()
        }
    }

    /// Closes the descriptor (idempotent, serialized onto the connection's I/O queue).
    public func close() async {
        closeDescriptor()
    }

    private func closeDescriptor() {
        guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else { return }
        let descriptor = self.descriptor
        ioQueue.async { try? descriptor.close() }
    }

    /// Wakes a stalled `read`/`write` on cancellation via `shutdown(2)` — directly, off the serial
    /// queue the blocking syscall occupies (a queued close would deadlock behind it).
    ///
    /// Skipped once `close()` has begun, so it can never act on a descriptor whose number the OS may
    /// have recycled.
    private func shutdownDescriptor() {
        guard !isClosed.load(ordering: .acquiring) else { return }
        _ = Darwin.shutdown(descriptor.rawValue, SHUT_RDWR)
    }

    /// Writes every byte of `bytes` to `descriptor`, advancing through a `RawSpan` and handling the
    /// short writes that `write(2)` is permitted to return.
    private static func writeAll(_ bytes: [UInt8], to descriptor: FileDescriptor) throws {
        try bytes.withUnsafeBytes { raw in
            let span = raw.bytes  // RawSpan view of the payload (zero-copy)
            var start = 0
            while start < span.byteCount {
                let chunk = span.extracting(start ..< span.byteCount)
                start += try chunk.withUnsafeBytes { try descriptor.write($0) }
            }
        }
    }
}
