//
//  POSIXSocket.swift
//  HTTPTransport
//
//  Shared POSIX sockets plumbing for the BSD-socket backbones (swift-system, Dispatch, kqueue):
//  create/bind/listen a TCP socket, toggle non-blocking mode, resolve the peer, and classify
//  accept() failures. Keeps the three backbones DRY and consistent.
//
//  Standards: socket()/setsockopt()/bind()/listen()/getsockname()/fcntl()/getaddrinfo()/getnameinfo()
//  per POSIX.1-2017 (IEEE Std 1003.1-2017). TCP (RFC 9293) over IPv4 (RFC 791) or IPv6 (RFC 4291) —
//  the family is chosen from the host literal, matching Network.framework's reach (audit T-F12).
//

internal import Darwin

/// Stateless POSIX sockets helpers shared by the BSD-socket transport backbones.
enum POSIXSocket {
    /// How an `accept()` failure should be handled by an accept loop.
    enum AcceptOutcome {
        /// `EAGAIN`/`EWOULDBLOCK` — no connection is pending right now (a non-blocking socket is drained).
        case wouldBlock
        /// Transient (`EINTR`/`ECONNABORTED`) or recoverable resource pressure — try again.
        case retry
        /// The listening descriptor is gone (`EBADF`/`EINVAL`) or unrecoverable — stop accepting.
        case stop
    }

    /// Creates, binds, and listens on a POSIX.1-2017 stream socket for IPv4 (RFC 791) or IPv6
    /// (RFC 4291), returning the descriptor and the OS-assigned port.
    ///
    /// The address family is resolved from `host` by `getaddrinfo` (a colon-bearing literal is IPv6),
    /// so a POSIX backbone reaches both families like Network.framework does (audit T-F12).
    static func makeListenSocket(
        // swiftlint:disable:next discouraged_default_parameter - reusePort is prefork opt-in
        host: String, port: UInt16, nonBlocking: Bool, reusePort: Bool = false, backlog: Int32
    ) throws -> (descriptor: Int32, port: UInt16) {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC  // IPv4 or IPv6, chosen from the host literal
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_PASSIVE  // a bindable (server) address
        var resolved: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &resolved) == 0, let info = resolved else {
            throw TransportError.bindFailed("getaddrinfo(\(host)) failed")
        }
        defer { freeaddrinfo(resolved) }
        let ai = info.pointee
        let rawFD = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol)
        guard rawFD >= 0 else { throw TransportError.bindFailed("socket() errno \(errno)") }

        var reuse: Int32 = 1
        _ = setsockopt(rawFD, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        if reusePort {
            // SO_REUSEPORT lets N prefork workers bind the same port; the kernel load-balances
            // accepted connections across them (a worker per core). Off by default so a second,
            // accidental instance still fails with EADDRINUSE rather than silently sharing the port.
            _ = setsockopt(
                rawFD,
                SOL_SOCKET,
                SO_REUSEPORT,
                &reuse,
                socklen_t(MemoryLayout<Int32>.size)
            )
        }
        setNoSIGPIPE(rawFD)
        if nonBlocking { setNonBlocking(rawFD) }

        guard bind(rawFD, ai.ai_addr, ai.ai_addrlen) == 0 else {
            let captured = errno
            close(rawFD)
            throw TransportError.bindFailed("bind() errno \(captured)")
        }
        guard listen(rawFD, backlog) == 0 else {
            let captured = errno
            close(rawFD)
            throw TransportError.bindFailed("listen() errno \(captured)")
        }
        return (rawFD, readBoundPort(of: rawFD))
    }

    /// Marks a descriptor non-blocking via `fcntl(F_SETFL, O_NONBLOCK)`.
    static func setNonBlocking(_ rawFD: Int32) {
        let flags = fcntl(rawFD, F_GETFL, 0)
        _ = fcntl(rawFD, F_SETFL, flags | O_NONBLOCK)
    }

    /// Suppresses `SIGPIPE` on `rawFD` so a `write` to a peer that has closed its read end returns
    /// `EPIPE` instead of delivering `SIGPIPE` — whose default disposition would terminate the whole
    /// server process, a one-packet remote DoS (audit T-F1).
    ///
    /// Darwin exposes this as the `SO_NOSIGPIPE` socket option (POSIX.1-2017 has no portable
    /// equivalent for `write`; Linux would use `MSG_NOSIGNAL` on `send`). Set on the listen socket and
    /// on every accepted client socket so the entire byte path fails closed via `TransportError`.
    static func setNoSIGPIPE(_ rawFD: Int32) {
        var on: Int32 = 1
        _ = setsockopt(rawFD, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    }

    /// Disables Nagle's algorithm via `TCP_NODELAY` so a sub-MSS response flushes immediately,
    /// not after the ~40 ms delayed-ACK coalesce window.
    ///
    /// Nagle inflates tail latency on the small / keep-alive responses HTTP serves (the p99.9 the
    /// Bench/ comparison exposed). Set on every accepted client socket (RFC 9293); per-connection,
    /// since the listen socket carries no data.
    static func setNoDelay(_ rawFD: Int32) {
        var on: Int32 = 1
        _ = setsockopt(rawFD, IPPROTO_TCP, TCP_NODELAY, &on, socklen_t(MemoryLayout<Int32>.size))
    }

    /// Reads the OS-assigned port via `getsockname()` (either address family).
    static func readBoundPort(of rawFD: Int32) -> UInt16 {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let ok = withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(rawFD, $0, &length) == 0
            }
        }
        guard ok else {
            return 0
        }
        return peerAddress(from: storage).port
    }

    /// Resolves the peer's numeric host and port from an accepted `sockaddr_storage` of either family
    /// (IPv4 RFC 791 / IPv6 RFC 4291) via `getnameinfo` — no per-family `inet_ntop` branching.
    static func peerAddress(from storage: sockaddr_storage) -> TransportAddress {
        var source = storage
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var service = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let length = socklen_t(source.ss_len)
        let status = withUnsafePointer(to: &source) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getnameinfo(
                    sockaddrPointer,
                    length,
                    &host,
                    socklen_t(host.count),
                    &service,
                    socklen_t(service.count),
                    NI_NUMERICHOST | NI_NUMERICSERV
                )
            }
        }
        guard status == 0 else {
            return TransportAddress(host: "", port: 0)
        }
        let port = UInt16(String(cString: service)) ?? 0
        return TransportAddress(host: String(cString: host), port: port)
    }

    /// Classifies an `accept()` failure (backs off briefly on fd exhaustion before retrying).
    static func classifyAcceptError(_ error: Int32) -> AcceptOutcome {
        switch error {
            case EAGAIN, EWOULDBLOCK:
                return .wouldBlock
            case EINTR, ECONNABORTED:
                return .retry
            case EMFILE, ENFILE:
                usleep(10_000)  // fd exhaustion — back off ~10 ms, then retry
                return .retry
            default:
                return .stop  // EBADF / EINVAL or unrecoverable
        }
    }

    /// Reads up to `maxLength` bytes via `read`, or returns `nil` at end of stream.
    ///
    /// One allocation, never zero-filled, trimmed to the count `read` reports (no slice copy), per the
    /// CLAUDE.md allocation rules. `read` writes into the buffer and returns the byte count it
    /// produced; a zero-length read is end of stream.
    static func readBuffer(
        maxLength: Int,
        _ read: (UnsafeMutableRawBufferPointer) throws -> Int
    ) rethrows -> [UInt8]? {
        let bytes = try [UInt8](unsafeUninitializedCapacity: max(1, maxLength)) { buffer, filled in
            filled = try read(UnsafeMutableRawBufferPointer(buffer))
        }
        return bytes.isEmpty ? nil : bytes
    }
}
