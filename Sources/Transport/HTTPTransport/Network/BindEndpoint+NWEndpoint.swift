//
//  BindEndpoint+NWEndpoint.swift
//  HTTPTransport
//
//  Bridges the backbone-agnostic ``BindEndpoint`` onto Network.framework's `NWEndpoint`, which is how
//  both Network-based backbones (TCP `NWListener`, QUIC `NWListener`/`NetworkListener`) are told which
//  local address to bind. Darwin-only by construction: the whole `Network/` directory is excluded from
//  the Linux build (see Package.swift).
//
//  Standards: IPv4 (RFC 791) and IPv6 (RFC 4291) literals; the scoped-literal `%zone` suffix of
//  RFC 4007 §11.2 is preserved through `IPv6Address`.
//

internal import Network

extension BindEndpoint {
    /// The Network.framework endpoint this bind endpoint names.
    ///
    /// Built from the already-resolved numeric literal, never from the operator's host string, so the
    /// listener cannot fall back to `NWEndpoint.Host.name` resolution — which on failure binds the
    /// wildcard and reports `.ready` instead of failing (measured; see ``BindEndpoint``).
    func networkEndpoint() throws(TransportError) -> NWEndpoint {
        let host: NWEndpoint.Host
        switch family {
            case .ipv4:
                guard let parsed = IPv4Address(address) else {
                    throw TransportError.bindFailed("unparseable IPv4 bind address \(address)")
                }
                host = .ipv4(parsed)
            case .ipv6:
                guard let parsed = IPv6Address(address) else {
                    throw TransportError.bindFailed("unparseable IPv6 bind address \(address)")
                }
                host = .ipv6(parsed)
        }
        // `NWEndpoint.Port(rawValue:)` is non-nil for every `UInt16`, including 0 — which *is*
        // `.any`, the explicit ephemeral request. The fallback keeps the no-force-unwrap rule
        // without changing behaviour.
        return .hostPort(host: host, port: NWEndpoint.Port(rawValue: port) ?? .any)
    }
}
