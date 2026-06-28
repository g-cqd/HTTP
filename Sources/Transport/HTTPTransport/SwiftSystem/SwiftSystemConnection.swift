//
//  SwiftSystemConnection.swift
//  HTTPTransport
//
//  A TransportConnection over an accepted socket, using apple/swift-system's typed FileDescriptor for
//  read/write/close — driven **event-driven** by the shared ``KqueueEventLoop`` (audit R4), NOT by a
//  blocking syscall on a worker thread. The socket is non-blocking; a read/write that would block parks
//  on kqueue readiness and resumes on the loop thread, and the serve task is pinned to that loop
//  (``preferredTaskExecutor``) so read → parse → respond → write run inline with no hop to the
//  cooperative pool. This is the swift-system-typed twin of ``POSIXKqueueConnection``: it shows the
//  swift-system `FileDescriptor` API is not inherently blocking — the prior blocking model was a choice,
//  not a limitation — and it inherits the same median + tail profile as the kqueue backbone.
//
//  Task cancellation closes the descriptor through the loop (``closeDescriptor(_:)``), which unblocks a
//  parked read/write so the continuation resumes with an error instead of leaking.
//
//  Standards: read()/write()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017) via swift-system's typed
//  wrappers; TCP (RFC 9293) over IPv4 (RFC 791). Readiness via BSD kqueue.
//

internal import Darwin
internal import Synchronization
internal import SystemPackage

/// A ``TransportConnection`` backed by a swift-system `FileDescriptor`, multiplexed by a
/// ``KqueueEventLoop`` (audit R4).
public final class SwiftSystemConnection: TransportConnection {
    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    /// The connection's own ``KqueueEventLoop`` — a `TaskExecutor` — so the server pins this
    /// connection's serve task to the loop and runs read → handler → write inline on the loop thread,
    /// with no hop to the cooperative pool (audit R4).
    public var preferredTaskExecutor: (any TaskExecutor)? { eventLoop }

    private let descriptor: FileDescriptor
    private let eventLoop: KqueueEventLoop
    private let isClosed = Atomic<Bool>(false)
    /// A reusable receive buffer, sized to `maxLength` on first use and overwritten each read, so the hot
    /// read path allocates no fresh chunk per `recv` (audit P1). `Mutex`-guarded because `read(2)` runs on
    /// the loop thread while the copy-out runs on the awaiting (pinned) task; reads on one connection are
    /// serial, so the lock is uncontended.
    private let scratch = Mutex<[UInt8]>([])

    private enum WriteOutcome {
        case done
        case wouldBlock(offset: Int)
        case failed(any Error)
    }

    /// A non-blocking `read`/`write` reported it would block — re-arm readiness rather than fail.
    private struct WouldBlock: Error {}

    /// Wraps an accepted, non-blocking socket `descriptor` watched by `eventLoop`.
    init(
        id: TransportConnectionID,
        descriptor: FileDescriptor,
        peer: TransportAddress,
        eventLoop: KqueueEventLoop
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.eventLoop = eventLoop
    }

    deinit {
        // Deliberately no fd close here: `close()` routes the shutdown through the loop so the descriptor
        // closes exactly once, serialized against any in-flight readiness handler. The owner calls `close()`.
    }

    /// Reads up to `maxLength` bytes once the socket is readable, or `nil` at end of stream.
    ///
    /// No per-op cancellation handler: the server registers one ``cancel()`` for the whole connection
    /// (audit CC4); cancelling the serve task closes the fd through the loop, which fires the parked
    /// readiness handler against the closed descriptor so this continuation resumes with an error.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        try await withUnsafeThrowingContinuation { continuation in
            readAvailable(maxLength: maxLength, into: OnceResumer(continuation))
        }
    }

    /// Reads up to `maxLength` bytes into the reused scratch and appends them to `buffer`, returning the
    /// count appended (`0` at EOF) — the allocation-free read path (audit P1).
    public func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        let count = try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Int, any Error>) in
            readIntoScratch(maxLength: maxLength, into: OnceResumer(continuation))
        }
        if count > 0 {
            scratch.withLock { buffer.append(contentsOf: $0[..<count]) }
        }
        return count
    }

    /// Writes all of `bytes`, re-arming on writability whenever the socket buffer is full.
    public func send(_ bytes: [UInt8]) async throws {
        try await withUnsafeThrowingContinuation {
            (continuation: UnsafeContinuation<Void, any Error>) in
            writeRemaining(bytes: bytes, offset: 0, once: OnceResumer(continuation))
        }
    }

    /// Closes the descriptor (idempotent, serialized on the loop to avoid an fd-reuse race).
    public func close() async {
        closeDescriptor()
    }

    /// Closes the descriptor synchronously to unblock a parked read/write (audit CC4) — the server's
    /// once-per-connection cancellation handler calls this; it is the idempotent ``closeDescriptor()``.
    public func cancel() {
        closeDescriptor()
    }

    private func closeDescriptor() {
        guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else {
            return
        }
        eventLoop.closeDescriptor(descriptor.rawValue)
    }

    /// Fills the reused scratch via `FileDescriptor.read` once readable and resumes `once` with the byte
    /// count (`0` at EOF), re-arming on a spurious `EAGAIN`.
    ///
    /// Runs on the loop thread.
    private func readIntoScratch(maxLength: Int, into once: OnceResumer<Int>) {
        do {
            let bytesRead = try scratch.withLock { (buffer: inout [UInt8]) throws -> Int in
                if buffer.count < maxLength {
                    buffer = [UInt8](repeating: 0, count: maxLength)  // sized once, then reused
                }
                return try buffer.withUnsafeMutableBytes { raw -> Int in
                    try Self.readOnce(
                        descriptor,
                        UnsafeMutableRawBufferPointer(rebasing: raw[..<maxLength])
                    )
                }
            }
            once.resume(returning: bytesRead)  // 0 == EOF
        }
        catch is WouldBlock {
            eventLoop.waitReadable(descriptor.rawValue) { [self] in
                readIntoScratch(maxLength: maxLength, into: once)
            }
        }
        catch {
            once.resume(throwing: error)
        }
    }

    private func readAvailable(maxLength: Int, into once: OnceResumer<[UInt8]?>) {
        do {
            let bytes = try POSIXSocket.readBuffer(maxLength: maxLength) { raw in
                try Self.readOnce(descriptor, raw)
            }
            once.resume(returning: bytes)  // nil == EOF
        }
        catch is WouldBlock {
            eventLoop.waitReadable(descriptor.rawValue) { [self] in
                readAvailable(maxLength: maxLength, into: once)
            }
        }
        catch {
            once.resume(throwing: error)
        }
    }

    /// One `FileDescriptor.read`, retrying `EINTR` and mapping `EAGAIN`/`EWOULDBLOCK` to ``WouldBlock``.
    private static func readOnce(
        _ descriptor: FileDescriptor,
        _ raw: UnsafeMutableRawBufferPointer
    ) throws -> Int {
        while true {
            do {
                return try descriptor.read(into: raw)
            }
            catch Errno.interrupted {
                continue  // signal before any byte — retry
            }
            catch let error as Errno
            where error == .wouldBlock || error == .resourceTemporarilyUnavailable {
                throw WouldBlock()  // spurious readiness / no data yet — re-arm
            }
        }
    }

    /// Writes `bytes[offset...]` via `FileDescriptor.write`; on `EAGAIN` re-arms writability and resumes
    /// from the new offset — iterative (event-driven), not recursive.
    ///
    /// Runs on the loop thread.
    private func writeRemaining(bytes: [UInt8], offset: Int, once: OnceResumer<Void>) {
        var offset = offset
        let outcome: WriteOutcome = bytes.withUnsafeBytes { raw in
            while offset < raw.count {
                do {
                    let written = try descriptor.write(
                        UnsafeRawBufferPointer(rebasing: raw[offset...])
                    )
                    offset += written
                }
                catch Errno.interrupted {
                    continue  // interrupted before any byte — retry
                }
                catch let error as Errno
                where error == .wouldBlock || error == .resourceTemporarilyUnavailable {
                    return .wouldBlock(offset: offset)
                }
                catch {
                    return .failed(error)
                }
            }
            return .done
        }
        switch outcome {
            case .done:
                once.resume(returning: ())
            case .failed(let error):
                once.resume(throwing: error)
            case .wouldBlock(let remaining):
                eventLoop.waitWritable(descriptor.rawValue) { [self] in
                    writeRemaining(bytes: bytes, offset: remaining, once: once)
                }
        }
    }
}
