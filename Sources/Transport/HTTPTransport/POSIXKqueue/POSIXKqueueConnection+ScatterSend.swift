//
//  POSIXKqueueConnection+ScatterSend.swift
//  HTTPTransport
//
//  3-buffer `writev(2)` scatter-gather send for HTTP/1.1 chunked streaming (`<hex>\r\n` + payload
//  + `\r\n`, issue #2), avoiding per-chunk payload copies on the kqueue backbone.
//

#if canImport(Darwin)
    internal import Darwin

    extension POSIXKqueueConnection {
        /// Sends `head`, `body`, and `tail` via 3-entry `writev(2)` scatter-gather with zero
        /// payload coalescing copy (issue #2).
        public func send(_ head: [UInt8], _ body: [UInt8], _ tail: [UInt8]) async throws {
            guard !tail.isEmpty else {
                try await send(head, body)
                return
            }
            guard !body.isEmpty else {
                try await send(head, tail)
                return
            }
            let fd = self.descriptor
            let loop = self.eventLoop
            try await sendOwner.withOwnership { resumer in
                // Safety: `claimSend` installs `continuation` in `OnceResumer`, guaranteeing
                // exact-once resumption on completion, write error, or close.
                try await unsafe withUnsafeThrowingContinuation {
                    (continuation: UnsafeContinuation<Void, any Error>) in
                    guard unsafe claimSend(continuation, resumer) else {
                        return
                    }
                    Self.pumpThreePartWritev(
                        parts: (head, body, tail),
                        offset: 0,
                        fd: fd,
                        loop: loop,
                        resumer: resumer
                    )
                }
            }
        }

        private static func pumpThreePartWritev(
            parts: ([UInt8], [UInt8], [UInt8]),
            offset: Int,
            fd: Int32,
            loop: KqueueEventLoop,
            resumer: OnceResumer<Void>
        ) {
            let result = executeThreePartWritev(parts: parts, startOffset: offset, fd: fd)
            if case .done = result {
                resumer.resume(returning: ())
                return
            }
            if case .failed(let code) = result {
                resumer.resume(throwing: TransportError.ioFailed("writev errno \(code)"))
                return
            }
            if case .wouldBlock(let nextOffset) = result {
                let armed = loop.waitWritable(fd) {
                    pumpThreePartWritev(
                        parts: parts,
                        offset: nextOffset,
                        fd: fd,
                        loop: loop,
                        resumer: resumer
                    )
                }
                if !armed {
                    resumer.resume(throwing: TransportError.closed)
                }
            }
        }

        private static func executeThreePartWritev(
            parts: ([UInt8], [UInt8], [UInt8]),
            startOffset: Int,
            fd: Int32
        ) -> WriteOutcome {
            let counts = (parts.0.count, parts.1.count, parts.2.count)
            return parts.0.withUnsafeBytes { r0 in
                parts.1.withUnsafeBytes { r1 in
                    parts.2.withUnsafeBytes { r2 in
                        guard let b0 = r0.baseAddress,
                            let b1 = r1.baseAddress,
                            let b2 = r2.baseAddress
                        else {
                            return .done
                        }
                        return drainThreeIovecs(
                            fd: fd,
                            bases: (b0, b1, b2),
                            counts: counts,
                            startOffset: startOffset
                        )
                    }
                }
            }
        }

        private static func drainThreeIovecs(
            fd: Int32,
            bases: (UnsafeRawPointer, UnsafeRawPointer, UnsafeRawPointer),
            counts: (Int, Int, Int),
            startOffset: Int
        ) -> WriteOutcome {
            var cursor = startOffset
            let boundary1 = counts.0 + counts.1
            let total = boundary1 + counts.2
            while cursor < total {
                var vecs = gatherIovecs(
                    bases: bases,
                    counts: counts,
                    boundary1: boundary1,
                    cursor: cursor
                )
                // Safety: all three backing arrays stay alive across the synchronous syscall.
                let n = unsafe writev(fd, &vecs, Int32(vecs.count))
                if n > 0 {
                    cursor += n
                    continue
                }
                let err = errno
                if n < 0, err == EINTR {
                    continue
                }
                if n < 0, err == EAGAIN || err == EWOULDBLOCK {
                    return .wouldBlock(offset: cursor)
                }
                return .failed(errno: err)
            }
            return .done
        }

        private static func gatherIovecs(
            bases: (UnsafeRawPointer, UnsafeRawPointer, UnsafeRawPointer),
            counts: (Int, Int, Int),
            boundary1: Int,
            cursor: Int
        ) -> [iovec] {
            var vecs: [iovec] = []
            vecs.reserveCapacity(3)
            if cursor < counts.0 {
                vecs.append(unsafe makeIOVec(bases.0 + cursor, counts.0 - cursor))
                vecs.append(unsafe makeIOVec(bases.1, counts.1))
                vecs.append(unsafe makeIOVec(bases.2, counts.2))
            }
            else if cursor < boundary1 {
                let delta = cursor - counts.0
                vecs.append(unsafe makeIOVec(bases.1 + delta, counts.1 - delta))
                vecs.append(unsafe makeIOVec(bases.2, counts.2))
            }
            else {
                let delta = cursor - boundary1
                vecs.append(unsafe makeIOVec(bases.2 + delta, counts.2 - delta))
            }
            return vecs
        }

        private static func makeIOVec(_ base: UnsafeRawPointer, _ length: Int) -> iovec {
            // `writev(2)` reads `iov_base` as const; Darwin's C struct uses `UnsafeMutableRawPointer`.
            unsafe iovec(iov_base: UnsafeMutableRawPointer(mutating: base), iov_len: length)
        }
    }
#endif
