//
//  POSIXDispatchConnection.swift
//  HTTPTransport
//
//  A TransportConnection over a non-blocking socket, driven by GCD `DispatchSource` readiness events
//  plus direct `read(2)`/`write(2)`. Unlike a `DispatchIO` channel — whose `read(length:)` operation
//  stays open until it has read the *full* length or hit EOF, so on a keep-alive socket it swallows the
//  next request's bytes and serializes the following read behind it — a readiness source consumes only
//  what is currently buffered and returns at once, which is exactly request/response framing needs.
//
//  Every descriptor access (read, write, close) runs on one per-connection *serial* queue, so a close
//  can never race a syscall on the same fd, and the fd is closed only after its source is cancelled.
//
//  Standards: the byte stream is TCP (RFC 9293) over IPv4 (RFC 791); read/write semantics follow
//  POSIX.1-2017 (IEEE Std 1003.1-2017).
//

internal import Darwin
internal import Dispatch
internal import Synchronization

/// A ``TransportConnection`` backed by GCD `DispatchSource` readiness over a non-blocking socket.
///
/// The `Atomic` close flag and the `Mutex`-guarded waiter make the type genuinely `Sendable`. Task
/// cancellation closes the descriptor, which unblocks (and fails) any parked read/write.
public final class POSIXDispatchConnection: TransportConnection {
    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    private let descriptor: Int32
    private let queue: DispatchQueue
    private let isClosed = Atomic<Bool>(false)
    private let waiter = Mutex<Waiter?>(nil)

    /// A parked read or write: its readiness source plus a closure that fails the awaiting continuation
    /// (read → EOF, write → error) when the connection is torn down out from under it.
    private struct Waiter {
        let source: any DispatchSourceProtocol
        let fail: @Sendable () -> Void
    }

    /// Spurious readiness: the source fired but `read(2)` returned `EAGAIN`; keep waiting.
    private struct WouldBlock: Error {}

    /// Wraps an accepted, non-blocking socket; the connection owns and eventually closes `descriptor`.
    init(
        id: TransportConnectionID, descriptor: Int32, peer: TransportAddress, queue: DispatchQueue
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.queue = queue
    }

    deinit {
        // No teardown beyond ARC.
    }

    // MARK: - Receive

    /// Reads up to `maxLength` currently-buffered bytes, or `nil` at end of stream.
    ///
    /// Arms a read source; when the socket is readable, one non-blocking `read(2)` returns what is
    /// buffered. Cancellation closes the descriptor to unblock a stalled read.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let fd = descriptor
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<[UInt8]?, any Error>) in
                let once = OnceResumer(continuation)
                queue.async { [self] in
                    guard !isClosed.load(ordering: .acquiring) else {
                        once.resume(returning: nil)
                        return
                    }
                    let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
                    waiter.withLock { $0 = Waiter(source: source) { once.resume(returning: nil) } }
                    source.setEventHandler { [self] in
                        do {
                            let bytes = try Self.readAvailable(fd, maxLength)
                            clearWaiter(source)
                            once.resume(returning: bytes)
                        }
                        catch is WouldBlock {
                            // Spurious readiness — leave the source armed; it fires again.
                        }
                        catch {
                            clearWaiter(source)
                            once.resume(throwing: error)
                        }
                    }
                    source.resume()
                }
            }
        } onCancel: {
            closeDescriptor()
        }
    }

    /// One non-blocking `read(2)` of the bytes buffered now (`nil` at EOF); throws `WouldBlock` if the
    /// readiness was spurious so the caller keeps waiting.
    private static func readAvailable(_ fd: Int32, _ maxLength: Int) throws -> [UInt8]? {
        try POSIXSocket.readBuffer(maxLength: maxLength) { raw in
            while true {
                let count = read(fd, raw.baseAddress, raw.count)
                if count >= 0 {
                    return count
                }
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlock() }
                throw TransportError.ioFailed("read errno \(errno)")
            }
        }
    }

    // MARK: - Send

    /// Writes all of `bytes`, awaiting socket writability across short writes (backpressure).
    public func send(_ bytes: [UInt8]) async throws {
        guard !bytes.isEmpty else {
            return
        }
        let fd = descriptor
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                let once = OnceResumer(continuation)
                queue.async { [self] in
                    guard !isClosed.load(ordering: .acquiring) else {
                        once.resume(throwing: TransportError.ioFailed("connection closed"))
                        return
                    }
                    writeFrom(0, fd: fd, bytes: bytes, once: once)
                }
            }
        } onCancel: {
            closeDescriptor()
        }
    }

    /// Writes `bytes[offset...]` with non-blocking `write(2)`; on `EAGAIN` arms a one-shot write source
    /// and resumes from the new offset once the socket drains — iterative (event-driven), not recursive.
    private func writeFrom(_ offset: Int, fd: Int32, bytes: [UInt8], once: OnceResumer<Void>) {
        let outcome: WriteOutcome = bytes.withUnsafeBytes { raw -> WriteOutcome in
            // Empty buffer (already guarded above).
            guard let base = raw.baseAddress else {
                return .done
            }
            var cursor = offset
            while cursor < raw.count {
                let written = write(fd, base + cursor, raw.count - cursor)
                if written > 0 {
                    cursor += written
                    continue
                }
                if written < 0 {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        return .wouldBlock(cursor)
                    }
                    return .failed(Int(errno))
                }
                return .wouldBlock(cursor)  // write returned 0
            }
            return .done
        }
        switch outcome {
            case .done:
                clearWaiter(nil)
                once.resume(returning: ())
            case .failed(let code):
                clearWaiter(nil)
                once.resume(throwing: TransportError.ioFailed("write errno \(code)"))
            case .wouldBlock(let next):
                let source = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: queue)
                waiter.withLock {
                    $0 = Waiter(source: source) {
                        once.resume(throwing: TransportError.ioFailed("connection closed"))
                    }
                }
                source.setEventHandler { [self] in
                    source.cancel()  // one-shot; writeFrom re-arms if it blocks again
                    writeFrom(next, fd: fd, bytes: bytes, once: once)
                }
                source.resume()
        }
    }

    private enum WriteOutcome {
        case done
        case wouldBlock(Int)
        case failed(Int)
    }

    // MARK: - Close

    /// Closes the connection idempotently.
    public func close() async {
        closeDescriptor()
    }

    /// Clears the parked waiter and cancels a completed read/write `source` (called on `queue`).
    private func clearWaiter(_ source: (any DispatchSourceProtocol)?) {
        waiter.withLock { $0 = nil }
        source?.cancel()
    }

    /// Closes the socket once, idempotently.
    ///
    /// `DispatchSource.cancel()` is asynchronous — a readiness handler the kernel just made ready may
    /// still be queued — so the fd is safe to close only once GCD has quiesced delivery, i.e. from the
    /// source's *cancellation handler*. Closing it inline after `cancel()` would race that handler onto
    /// a since-reused fd (cross-connection corruption). With no source armed there is no watcher, so an
    /// inline close is correct. Runs on `queue`.
    private func closeDescriptor() {
        guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else {
            return
        }
        let fd = descriptor
        queue.async { [self] in
            let parked = waiter.withLock { current -> Waiter? in
                defer { current = nil }
                return current
            }
            guard let parked else {
                Darwin.close(fd)  // no armed source watching the fd → safe to close directly
                return
            }
            parked.source.setCancelHandler {
                Darwin.close(fd)  // GCD guarantees delivery has stopped before this runs
                parked.fail()  // unblock the parked receive/send (EOF / error)
            }
            parked.source.cancel()
        }
    }
}
