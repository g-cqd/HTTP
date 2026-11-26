//
//  HTTPOrigin.swift
//  HTTPClient
//
//  RFC 6454 / RFC 9110 §4.3.1 — the `(scheme, host, port)` triple a request targets, which is also
//  the connection-pool key: connections are only ever reused for the exact origin they dialed.
//

/// The `(scheme, host, port)` a request targets (RFC 9110 §4.3.1).
struct HTTPOrigin: Hashable, Sendable, CustomStringConvertible {
    let scheme: String
    let host: String
    let port: UInt16

    var isSecure: Bool { scheme == "https" }

    var description: String { "\(scheme)://\(host):\(port)" }

    /// The `Host` value (RFC 9110 §7.2): the port is omitted when it is the scheme default.
    var hostHeader: String {
        let bracketed = host.contains(":") ? "[\(host)]" : host
        let defaultPort: UInt16 = isSecure ? 443 : 80
        return port == defaultPort ? bracketed : "\(bracketed):\(port)"
    }

    /// Parses `scheme` + `authority` (`host`, `host:port`, `[v6]`, `[v6]:port`), rejecting userinfo.
    init(scheme rawScheme: String?, authority: String?) throws(HTTPClientError) {
        let scheme = (rawScheme ?? "https").lowercased()
        guard scheme == "https" || scheme == "http" else {
            throw .invalidRequest("unsupported scheme \(scheme)")
        }
        guard let authority, !authority.isEmpty, !authority.contains("@") else {
            throw .invalidRequest("missing or invalid authority")
        }
        var host = authority
        var port: UInt16 = scheme == "https" ? 443 : 80
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else {
                throw .invalidRequest("unterminated IPv6 literal")
            }
            host = String(authority[authority.index(after: authority.startIndex) ..< close])
            let rest = authority[authority.index(after: close)...]
            if rest.hasPrefix(":") {
                guard let parsed = UInt16(rest.dropFirst()), parsed > 0 else {
                    throw .invalidRequest("invalid port")
                }
                port = parsed
            }
            else if !rest.isEmpty {
                throw .invalidRequest("invalid authority")
            }
        }
        else if let colon = authority.lastIndex(of: ":") {
            host = String(authority[..<colon])
            guard let parsed = UInt16(authority[authority.index(after: colon)...]), parsed > 0
            else {
                throw .invalidRequest("invalid port")
            }
            port = parsed
        }
        guard !host.isEmpty else {
            throw .invalidRequest("empty host")
        }
        self.scheme = scheme
        self.host = host.lowercased()
        self.port = port
    }
}
