//
//  POSIXEpollConnection.swift
//  HTTPTransport
//
//  The Linux mirror of ``POSIXKqueueConnection``: a TransportConnection driven entirely by a
//  hand-rolled `epoll(7)` loop over a non-blocking socket. Reads wait for read readiness then read()
//  what is available; writes loop until drained, re-arming on write readiness whenever the socket
//  buffer fills. The write re-arm is event-driven (each step a fresh epoll callback) — NOT stack
//  recursion, so hostile peers cannot grow the stack. Writes go through `send(..., MSG_NOSIGNAL)` so a
//  peer RST mid-write yields `EPIPE` rather than a fatal `SIGPIPE` (Linux has no `SO_NOSIGPIPE`; audit T-F1).
//
//  Verified on Linux (Swift 6.5-dev, Ubuntu noble) — gated `#if canImport(Glibc)`; see ``EpollEventLoop``.
//
//  Standards: read()/send()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP (RFC 9293) over
//  IPv4 (RFC 791) / IPv6 (RFC 4291). Readiness via Linux epoll(7).
//

#if canImport(Glibc)

    internal import Glibc
    internal import Synchronization

    /// A ``TransportConnection`` whose readiness is multiplexed by an ``EpollEventLoop``.
    ///
    /// The descriptor and `Atomic` close flag are the only state; close is idempotent and serialized on
    /// the event loop. Task cancellation closes the descriptor to unblock a pending read.
    public final class POSIXEpollConnection: TransportConnection {
        /// The connection's stable identifier.
        public let id: TransportConnectionID

        /// The peer's address.
        public let peer: TransportAddress

        private let descriptor: Int32
        private let eventLoop: EpollEventLoop
        private let isClosed = Atomic<Bool>(false)

        private enum WriteOutcome {
            case done
            case wouldBlock(offset: Int)
            case failed(errno: Int32)
        }

        /// Wraps an accepted, non-blocking socket descriptor watched by `eventLoop`.
        init(
            id: TransportConnectionID,
            descriptor: Int32,
            peer: TransportAddress,
            eventLoop: EpollEventLoop
        ) {
            self.id = id
            self.peer = peer
            self.descriptor = descriptor
            self.eventLoop = eventLoop
        }

        deinit {
            // No teardown beyond ARC.
        }

        /// Reads up to `maxLength` bytes once the socket is readable, or `nil` at end of stream.
        public func receive(maxLength: Int) async throws -> [UInt8]? {
            let descriptor = self.descriptor
            let eventLoop = self.eventLoop
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let once = OnceResumer(continuation)
                    eventLoop.waitReadable(descriptor) {
                        Self.readAvailable(
                            descriptor: descriptor,
                            maxLength: maxLength,
                            eventLoop: eventLoop,
                            into: once
                        )
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
                        bytes: bytes,
                        offset: 0,
                        descriptor: descriptor,
                        eventLoop: eventLoop,
                        once: once
                    )
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
            guard !isClosed.exchange(true, ordering: .acquiringAndReleasing) else {
                return
            }
            eventLoop.closeDescriptor(descriptor)
        }

        /// A non-blocking `read` reported it would block — re-arm readability rather than fail (audit T-F3).
        private struct WouldBlockOnRead: Error {}

        private static func readAvailable(
            descriptor: Int32,
            maxLength: Int,
            eventLoop: EpollEventLoop,
            into once: OnceResumer<[UInt8]?>
        ) {
            do {
                let bytes = try POSIXSocket.readBuffer(maxLength: maxLength) { raw -> Int in
                    while true {
                        let count = read(descriptor, raw.baseAddress, raw.count)
                        if count >= 0 {
                            return count
                        }
                        // EINTR: interrupted before any data — retry. EAGAIN: spurious wakeup (data
                        // consumed elsewhere) — re-arm, don't fail.
                        if errno == EINTR { continue }
                        if errno == EAGAIN || errno == EWOULDBLOCK { throw WouldBlockOnRead() }
                        throw TransportError.ioFailed("read errno \(errno)")
                    }
                }
                once.resume(returning: bytes)  // nil == EOF (a zero-length read)
            }
            catch is WouldBlockOnRead {
                eventLoop.waitReadable(descriptor) {
                    readAvailable(
                        descriptor: descriptor,
                        maxLength: maxLength,
                        eventLoop: eventLoop,
                        into: once
                    )
                }
            }
            catch {
                once.resume(throwing: error)
            }
        }

        private static func writeRemaining(
            bytes: [UInt8],
            offset: Int,
            descriptor: Int32,
            eventLoop: EpollEventLoop,
            once: OnceResumer<Void>
        ) {
            var offset = offset
            let outcome: WriteOutcome = bytes.withUnsafeBytes { raw in
                while offset < raw.count {
                    // `MSG_NOSIGNAL`: a write to a peer that closed its read end returns EPIPE instead of
                    // raising SIGPIPE (Linux's per-call equivalent of Darwin's SO_NOSIGPIPE — audit T-F1).
                    // `Glibc.send` (not the `send(_:)` instance method, which would shadow it here).
                    let written = Glibc.send(
                        descriptor,
                        raw.baseAddress?.advanced(by: offset),
                        raw.count - offset,
                        Int32(MSG_NOSIGNAL)
                    )
                    if written > 0 {
                        offset += written
                    }
                    else if written < 0, errno == EINTR {
                        continue  // interrupted before any byte — retry (audit T-F3)
                    }
                    else if written < 0, errno == EWOULDBLOCK || errno == EAGAIN {
                        return .wouldBlock(offset: offset)
                    }
                    else {
                        return .failed(errno: errno)
                    }
                }
                return .done
            }
            switch outcome {
                case .done:
                    once.resume(returning: ())
                case .failed(let code):
                    once.resume(throwing: TransportError.ioFailed("send errno \(code)"))
                case .wouldBlock(let remaining):
                    eventLoop.waitWritable(descriptor) {
                        writeRemaining(
                            bytes: bytes,
                            offset: remaining,
                            descriptor: descriptor,
                            eventLoop: eventLoop,
                            once: once
                        )
                    }
            }
        }
    }

#endif
