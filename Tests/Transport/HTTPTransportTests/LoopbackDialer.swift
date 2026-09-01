//
//  LoopbackDialer.swift
//  HTTPTransportTests
//
//  A raw loopback TCP client, on every platform the package builds for.
//
//  It used to live in `LoopbackSupport.swift`, which cannot leave Darwin: the three `assertLoopback*`
//  round-trips there drive an `NWConnection` through `NetworkFrameworkConnection`, so that file is
//  excluded from the Linux graph and everything in it went with it. This function has no such
//  dependency — it is `socket(2)` + `connect(2)` — and it was the only thing keeping
//  `AcceptBackpressureTests` Darwin-only, which mattered because the `AcceptGate` that suite pins is
//  SHARED with the epoll backbone.
//
//  Standards: `socket(2)`, `connect(2)`, `close(2)` per POSIX.1-2017 (IEEE Std 1003.1-2017); TCP
//  (RFC 9293) over IPv4 (RFC 791).
//

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// Opens a blocking loopback TCP connection to `port`, returning its descriptor (`-1` on failure).
///
/// A raw descriptor rather than a `TransportConnection`: the accept-path tests need a client the
/// server has *not* accepted yet, which is the state the admission ceiling is about.
func openLoopbackConnection(to port: UInt16) -> Int32 {
    // Glibc vends SOCK_STREAM as the C enum `__socket_type` while `socket` takes Int32 — the same
    // divergence `POSIXSocket` normalizes on the source side.
    #if canImport(Glibc)
        let streamType = Int32(SOCK_STREAM.rawValue)
    #else
        let streamType = SOCK_STREAM
    #endif
    let descriptor = socket(AF_INET, streamType, 0)
    guard descriptor >= 0 else {
        return -1
    }
    var address = sockaddr_in()
    // `sin_len` is a BSD extension; Linux's `sockaddr_in` has no such field.
    #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    #endif
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    let connected = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
        }
    }
    guard connected else {
        close(descriptor)
        return -1
    }
    return descriptor
}
