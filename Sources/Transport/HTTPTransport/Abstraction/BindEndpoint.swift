//
//  BindEndpoint.swift
//  HTTPTransport
//
//  The ONE definition of what ``TransportConfiguration/host`` and ``TransportConfiguration/port``
//  mean. Every backbone binds the endpoint this type resolves, so "bind 127.0.0.1" is the same
//  instruction on Network.framework, kqueue, swift-system, Dispatch, epoll and QUIC — the drift that
//  audit findings F-04 (QUIC ignored the port) and F-05 (Network.framework ignored the host) were
//  each half of.
//
//  Resolution is `getaddrinfo(3)` with `AI_PASSIVE` (POSIX.1-2017) — the same call
//  ``POSIXSocket/makeListenSocket(host:port:nonBlocking:reusePort:backlog:)`` already makes — and the
//  result is normalized back to a numeric literal with `getnameinfo(3)` + `NI_NUMERICHOST`. Handing
//  Network.framework a *numeric* address rather than the operator's string is deliberate: an
//  `NWEndpoint.Host.name` that does not resolve makes `NWListener` bind the wildcard and report
//  `.ready` (measured on macOS 27 — see BackboneConformanceTests), i.e. it silently widens the bind
//  from "this interface" to "every interface". Resolving first turns that into a closed failure
//  (CWE-1188: insecure default; CWE-668: exposure to an unintended actor).
//
//  Standards: getaddrinfo/getnameinfo per POSIX.1-2017 (IEEE Std 1003.1-2017); IPv4 (RFC 791) and
//  IPv6 (RFC 4291) address literals; IPv6 scoped literals per RFC 4007 §11.2; the IPv4 wildcard
//  `0.0.0.0` (RFC 1122 §3.2.1.3) and the IPv6 wildcard `::` (RFC 4291 §2.5.2). Reserved documentation
//  ranges that a host cannot be assigned come from RFC 5737 (IPv4) and RFC 3849 (IPv6).
//

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// The local address and port a listener binds, resolved once from a ``TransportConfiguration``.
///
/// Resolution happens exactly once per ``ServerTransport/start(admission:)``, never on the accept or
/// byte path: a `getaddrinfo` call per accepted connection would put a DNS-capable syscall in the hot
/// loop. The resolved ``address`` is always a numeric literal, so a backbone never re-parses the
/// operator's string and two backbones can never disagree about which interface a name meant.
public struct BindEndpoint: Sendable, Equatable {
    /// The address family a resolved bind endpoint belongs to.
    public enum Family: Sendable, Equatable {
        /// IPv4 (RFC 791).
        case ipv4
        /// IPv6 (RFC 4291).
        case ipv6
    }

    /// The numeric address literal to bind (e.g. `"127.0.0.1"`, `"::1"`, `"0.0.0.0"`, `"::"`).
    public let address: String

    /// The address family ``address`` belongs to.
    public let family: Family

    /// The port to bind; `0` requests an OS-chosen ephemeral port.
    public let port: UInt16

    /// Whether ``address`` is the family's wildcard — every local interface, present and future.
    ///
    /// `0.0.0.0` (RFC 1122 §3.2.1.3) for IPv4 and `::` (RFC 4291 §2.5.2) for IPv6. A wildcard bind is
    /// an *explicit* request to be reachable off-host; anything else is an interface pin.
    public let isWildcard: Bool

    /// Whether the configuration asked the OS to choose the port (`port == 0`).
    ///
    /// Kept as an explicit, first-class request rather than a sentinel a backbone might "helpfully"
    /// override: the tests and the `Alt-Svc` advertisement (RFC 7838) both need "ephemeral, then tell
    /// me what you actually got".
    public var isEphemeralPortRequest: Bool {
        port == 0
    }

    /// Creates a bind endpoint from an already-numeric address.
    ///
    /// Prefer ``resolve(host:port:)``; this initializer exists for the resolver and for tests that
    /// need to construct an endpoint without touching the resolver.
    public init(address: String, family: Family, port: UInt16) {
        self.address = address
        self.family = family
        self.port = port
        isWildcard =
            switch family {
                case .ipv4:
                    address == "0.0.0.0"
                case .ipv6:
                    address == "::"
            }
    }

    /// Resolves the host and port of `configuration` into the endpoint its listener must bind.
    public static func resolve(
        _ configuration: TransportConfiguration
    ) throws(TransportError) -> Self {
        try resolve(host: configuration.host, port: configuration.port)
    }

    /// Resolves a configured `host` and `port` into the endpoint a listener must bind.
    ///
    /// `host` may be an IPv4 or IPv6 literal (with an optional RFC 4007 §11.2 zone), one of the two
    /// wildcards, or a name. A name is resolved here, once, and the first `AI_PASSIVE` answer wins —
    /// the same rule `getaddrinfo`-based POSIX binding already follows. A host that resolves to
    /// nothing throws ``TransportError/bindFailed(_:)``; the caller must not fall back to the
    /// wildcard, which would silently widen the listener's exposure.
    public static func resolve(
        host: String, port: UInt16
    ) throws(TransportError) -> Self {
        // SE-0458 (ADR 0009): `addrinfo` and the `getaddrinfo` family are unsafe by import. Every
        // pointer below is owned by the resolver and released by the `defer`ed `freeaddrinfo`, no
        // pointer outlives this call, and the only value that escapes is a `String` copied out of the
        // resolver's storage — so the unsafety is bounded by this function body.
        // IPv4 or IPv6, chosen from the host literal or from the name's first answer.
        var hints = unsafe addrinfo()
        unsafe hints.ai_family = AF_UNSPEC
        // `SOCK_STREAM` imports as a plain `Int32` on Darwin but as the `__socket_type` enum on Glibc.
        // The socket type only narrows *service-name* lookups, and the service below is always numeric,
        // so the resolved address is identical for the UDP-borne QUIC listeners (RFC 9000 over RFC 768).
        #if canImport(Darwin)
            unsafe hints.ai_socktype = SOCK_STREAM
        #else
            unsafe hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #endif
        unsafe hints.ai_flags = AI_PASSIVE  // a bindable (server) address
        var resolved: UnsafeMutablePointer<addrinfo>?
        guard unsafe getaddrinfo(host, String(port), &hints, &resolved) == 0,
            let info = unsafe resolved
        else {
            throw TransportError.bindFailed("getaddrinfo(\(host)) resolved no bindable address")
        }
        defer { unsafe freeaddrinfo(resolved) }
        let candidate = unsafe info.pointee
        let family: Family
        switch unsafe candidate.ai_family {
            case AF_INET:
                family = .ipv4
            case AF_INET6:
                family = .ipv6
            default:
                let reported = unsafe candidate.ai_family
                throw TransportError.bindFailed(
                    "getaddrinfo(\(host)) returned unsupported family \(reported)"
                )
        }
        guard let socketAddress = unsafe candidate.ai_addr,
            let literal = unsafe numericHost(
                of: socketAddress, length: unsafe candidate.ai_addrlen
            )
        else {
            throw TransportError.bindFailed("getaddrinfo(\(host)) returned an unreadable address")
        }
        return Self(address: literal, family: family, port: port)
    }

    /// Renders the endpoint the way an operator writes it: `127.0.0.1:8080`, `[::1]:8080` (RFC 3986
    /// §3.2.2).
    public var description: String {
        switch family {
            case .ipv4:
                "\(address):\(port)"
            case .ipv6:
                "[\(address)]:\(port)"
        }
    }

    /// Reads a resolved `sockaddr` back as a numeric host literal via `getnameinfo` + `NI_NUMERICHOST`.
    ///
    /// SE-0458 (ADR 0009): `socketAddress` is borrowed from the caller's live `addrinfo` chain and is
    /// only read; `buffer` is `NI_MAXHOST` octets, the size `getnameinfo` is contracted to respect,
    /// and neither pointer escapes.
    private static func numericHost(
        of socketAddress: UnsafeMutablePointer<sockaddr>, length: socklen_t
    ) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = unsafe getnameinfo(
            socketAddress,
            length,
            &buffer,
            socklen_t(buffer.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        guard status == 0 else {
            return nil
        }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: Unicode.UTF8.self)
    }
}
