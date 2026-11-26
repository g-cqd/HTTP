//
//  HTTPClientURL.swift
//  HTTPClient
//
//  RFC 3986 §3 / §5 — the minimal absolute-URL split the client needs (`scheme://authority/path?query`,
//  fragment dropped) and redirect `Location` resolution (absolute, network-path `//host/…`,
//  absolute-path `/…`, and relative-path references against the current path).
//

/// An absolute `http(s)` URL split into request components.
struct HTTPClientURL: Sendable, Equatable {
    let scheme: String
    let authority: String
    /// Origin-form request target (`/path?query`).
    let path: String

    /// Parses an absolute URL.
    init(_ raw: String) throws(HTTPClientError) {
        guard let separator = raw.firstRange(of: "://") else {
            throw .invalidRequest("not an absolute URL: \(raw)")
        }
        let scheme = raw[..<separator.lowerBound].lowercased()
        guard scheme == "http" || scheme == "https" else {
            throw .invalidRequest("unsupported scheme \(scheme)")
        }
        var rest = raw[separator.upperBound...]
        if let hash = rest.firstIndex(of: "#") {
            rest = rest[..<hash]
        }
        let pathStart = rest.firstIndex { $0 == "/" || $0 == "?" } ?? rest.endIndex
        let authority = String(rest[..<pathStart])
        guard !authority.isEmpty, !authority.contains("@") else {
            throw .invalidRequest("invalid authority in \(raw)")
        }
        var path = String(rest[pathStart...])
        if path.isEmpty {
            path = "/"
        }
        else if path.hasPrefix("?") {
            path = "/" + path
        }
        try Self.validate(path)
        self.scheme = scheme
        self.authority = authority
        self.path = path
    }

    /// Resolves a redirect `Location` against the current origin and request path (RFC 3986 §5.2).
    init(
        _ location: String, relativeTo origin: HTTPOrigin, path currentPath: String
    ) throws(HTTPClientError) {
        if location.contains("://") {
            try self.init(location)
            return
        }
        let base = "\(origin.scheme)://\(origin.hostHeader)"
        if location.hasPrefix("//") {
            try self.init("\(origin.scheme):\(location)")
        }
        else if location.hasPrefix("/") {
            try self.init(base + location)
        }
        else {
            let pathOnly =
                currentPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "/"
            let directory = pathOnly.lastIndex(of: "/").map { String(pathOnly[...$0]) } ?? "/"
            try self.init(base + directory + location)
        }
    }

    /// Rejects control octets and whitespace in the request target (request-smuggling guard).
    private static func validate(_ path: String) throws(HTTPClientError) {
        for byte in path.utf8 where byte <= 0x20 || byte == 0x7F {
            throw .invalidRequest("invalid octet in request target")
        }
    }
}
