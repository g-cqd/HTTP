//
//  POSIXSocket.swift
//  HTTPTransport
//
//  Shared POSIX sockets plumbing for the BSD-socket backbones (swift-system, Dispatch, kqueue):
//  create/bind/listen a TCP socket, toggle non-blocking mode, resolve the peer, and classify
//  accept() failures. Keeps the three backbones DRY and consistent.
//
//  Standards: socket()/setsockopt()/bind()/listen()/getsockname()/fcntl()/inet_pton()/inet_ntop()
//  per POSIX.1-2017 (IEEE Std 1003.1-2017). TCP (RFC 9293) over IPv4 (RFC 791).
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

    /// Creates, binds (IPv4, RFC 791), and listens (TCP, RFC 9293) on a POSIX.1-2017 stream socket,
    /// returning the descriptor and the OS-assigned port.
    static func makeListenSocket(
        // swiftlint:disable:next discouraged_default_parameter - reusePort is prefork opt-in
        host: String, port: UInt16, nonBlocking: Bool, backlog: Int32, reusePort: Bool = false
    ) throws -> (descriptor: Int32, port: UInt16) {
        let rawFD = socket(AF_INET, SOCK_STREAM, 0)
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

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard host.withCString({ inet_pton(AF_INET, $0, &address.sin_addr) }) == 1 else {
            close(rawFD)
            throw TransportError.bindFailed("invalid IPv4 host \(host)")
        }

        let bindStatus = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(rawFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindStatus == 0 else {
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

    /// Reads the OS-assigned port via `getsockname()`.
    static func readBoundPort(of rawFD: Int32) -> UInt16 {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(rawFD, $0, &length)
            }
        }
        return UInt16(bigEndian: address.sin_port)
    }

    /// Resolves the peer's IPv4 address from a `sockaddr_in` (RFC 791) via `inet_ntop`.
    static func peerAddress(from address: sockaddr_in) -> TransportAddress {
        var source = address
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        withUnsafePointer(to: &source.sin_addr) { addressPointer in
            _ = inet_ntop(AF_INET, addressPointer, &buffer, socklen_t(INET_ADDRSTRLEN))
        }
        let host = String(
            decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
            as: Unicode.UTF8.self
        )
        return TransportAddress(host: host, port: UInt16(bigEndian: address.sin_port))
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
