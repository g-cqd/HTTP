//
//  POSIXEpollConnection+Send.swift
//  HTTPTransport
//
//  The outbound pump of ``POSIXEpollConnection``, split out of the type's own file purely for the
//  400-line cap: the direction-ownership contract (audit F-03) added the lease assertions and the
//  ungated-core split that pushed it over. Nothing here is reachable except through
//  ``POSIXEpollConnection/send(_:)``, ``send(_:_:)`` and ``sendFile(descriptor:offset:length:)``,
//  each of which owns the outbound direction for the whole of the retry loop below — so every
//  re-arm in this file runs under the same lease as the first syscall that started it.
//
//  Each step is event-driven: a full socket buffer re-arms on write readiness and resumes from the
//  advanced offset on a fresh epoll callback, so a hostile peer that never drains cannot grow the
//  stack. Writes carry `MSG_NOSIGNAL` so a peer RST mid-write yields `EPIPE` rather than a fatal
//  `SIGPIPE` (Linux has no `SO_NOSIGPIPE`; audit T-F1).
//
//  Verified on Linux (see ``EpollEventLoop``); gated `#if canImport(Glibc)`.
//
//  Standards: send()/sendmsg()/sendfile() per POSIX.1-2017 (IEEE Std 1003.1-2017) plus the Linux
//  `MSG_NOSIGNAL` extension; TCP (RFC 9293).
//

#if canImport(Glibc)

    internal import CEpoll
    internal import Glibc

    extension POSIXEpollConnection {
        // The three pump entry points are `internal` rather than `private` only because the file split
        // put them across a file boundary from their callers; `sendScatter` below, which no other file
        // reaches, stays private.

        /// How far one pump step got before it had to stop.
        private enum WriteOutcome {
            case done
            case wouldBlock(offset: Int)
            case failed(errno: Int32)
        }

        /// One event-driven `sendfile(2)` pump step — Linux semantics: a positive return is the
        /// (possibly partial) count sent, `0` means the file ended early, `-1`/`EAGAIN` means the
        /// socket buffer is full with nothing sent.
        static func sendFileRemaining(
            file: Int32,
            offset: Int,
            remaining: Int,
            socket: Int32,
            eventLoop: EpollEventLoop,
            once: OnceResumer<Void>
        ) {
            var offset = offset
            var remaining = remaining
            while remaining > 0 {
                let sent = CEpoll_sendfile(socket, file, CLong(offset), CUnsignedLong(remaining))
                if sent > 0 {
                    offset += Int(sent)
                    remaining -= Int(sent)
                    continue
                }
                if sent == 0 {
                    // EOF before the framed length — never stop silently short (audit F1).
                    once.resume(
                        throwing: TransportError.ioFailed(
                            "sendFile: file ended \(remaining) octet(s) short of the framed length"
                        )
                    )
                    return
                }
                if errno == EINTR {
                    continue  // interrupted before any byte — retry (audit T-F3)
                }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    // Immutable copies for the @Sendable re-arm closure.
                    let nextOffset = offset
                    let nextRemaining = remaining
                    let registered = eventLoop.waitWritable(socket) {
                        sendFileRemaining(
                            file: file,
                            offset: nextOffset,
                            remaining: nextRemaining,
                            socket: socket,
                            eventLoop: eventLoop,
                            once: once
                        )
                    }
                    if !registered {
                        // See ``writeRemaining``: never park behind a refused registration.
                        once.resume(throwing: TransportError.closed)
                    }
                    return
                }
                once.resume(throwing: TransportError.ioFailed("sendfile errno \(errno)"))
                return
            }
            once.resume(returning: ())
        }

        static func writeRemaining(
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
                    let registered = eventLoop.waitWritable(descriptor) {
                        writeRemaining(
                            bytes: bytes,
                            offset: remaining,
                            descriptor: descriptor,
                            eventLoop: eventLoop,
                            once: once
                        )
                    }
                    if !registered {
                        // The descriptor died under us (a concurrent close/cancel raced this re-arm):
                        // fail the waiter rather than park behind a registration that can never fire.
                        once.resume(throwing: TransportError.closed)
                    }
            }
        }

        /// Writes `head` then `body` as one scatter-gather message, advancing one combined offset across
        /// the two buffers and re-arming on writability when the socket buffer fills — iterative
        /// (event-driven), not recursive.
        ///
        /// Uses `sendmsg(..., MSG_NOSIGNAL)` rather than `writev`: `writev` cannot carry `MSG_NOSIGNAL`,
        /// and Linux has no `SO_NOSIGPIPE`, so a bare `writev` would let a peer RST mid-write raise a fatal
        /// `SIGPIPE` (the one-packet DoS audit T-F1 closes). `sendmsg` is the scatter-gather form that
        /// takes the flag — `msg_iov`/`msg_iovlen` gather exactly as `writev(2)`.
        static func writevRemaining(
            head: [UInt8],
            body: [UInt8],
            offset: Int,
            descriptor: Int32,
            eventLoop: EpollEventLoop,
            once: OnceResumer<Void>
        ) {
            var offset = offset
            let total = head.count + body.count
            let outcome: WriteOutcome = head.withUnsafeBytes { headRaw in
                body.withUnsafeBytes { bodyRaw in
                    guard
                        let headBase = headRaw.baseAddress, let bodyBase = bodyRaw.baseAddress
                    else {
                        // Both buffers are non-empty by construction (body guarded, head is status).
                        return WriteOutcome.done
                    }
                    while offset < total {
                        // Gather vector for the unwritten tail: still within the head (head slice +
                        // whole body), or already past it (a body slice only).
                        var iovecs: [iovec]
                        if offset < head.count {
                            let headPtr = UnsafeMutableRawPointer(mutating: headBase + offset)
                            let bodyPtr = UnsafeMutableRawPointer(mutating: bodyBase)
                            iovecs = [
                                iovec(iov_base: headPtr, iov_len: head.count - offset),
                                iovec(iov_base: bodyPtr, iov_len: body.count)
                            ]
                        }
                        else {
                            let bodyOffset = offset - head.count
                            let bodyPtr = UnsafeMutableRawPointer(mutating: bodyBase + bodyOffset)
                            iovecs = [iovec(iov_base: bodyPtr, iov_len: body.count - bodyOffset)]
                        }
                        let written = sendScatter(descriptor, &iovecs)
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
            }
            switch outcome {
                case .done:
                    once.resume(returning: ())
                case .failed(let code):
                    once.resume(throwing: TransportError.ioFailed("sendmsg errno \(code)"))
                case .wouldBlock(let remaining):
                    let registered = eventLoop.waitWritable(descriptor) {
                        writevRemaining(
                            head: head,
                            body: body,
                            offset: remaining,
                            descriptor: descriptor,
                            eventLoop: eventLoop,
                            once: once
                        )
                    }
                    if !registered {
                        // See ``writeRemaining``: never park behind a refused registration.
                        once.resume(throwing: TransportError.closed)
                    }
            }
        }

        /// Sends one gather vector via `sendmsg(..., MSG_NOSIGNAL)`, returning its raw result.
        ///
        /// `msghdr()` zero-fills the header (no name, no control bytes, no flags); only `msg_iov` and
        /// `msg_iovlen` are set. `MSG_NOSIGNAL` is the per-call SIGPIPE suppression Linux lacks as a
        /// socket option (audit T-F1) — `writev` could not carry it.
        private static func sendScatter(_ descriptor: Int32, _ iovecs: inout [iovec]) -> Int {
            iovecs.withUnsafeMutableBufferPointer { iov -> Int in
                var message = msghdr()
                message.msg_iov = iov.baseAddress
                message.msg_iovlen = iov.count
                return sendmsg(descriptor, &message, Int32(MSG_NOSIGNAL))
            }
        }
    }

#endif
