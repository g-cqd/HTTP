//
//  RequestParser+HostValidation.swift
//  HTTP1
//
//  RFC 9110 §7.2 / RFC 3986 §3.2.2 — strict syntactic validation of the HTTP/1.1 `Host` header
//  (`uri-host [ ":" port ]`), closing Host-header injection, userinfo spoofing (`evil@good`),
//  whitespace/path delimiters, and out-of-range ports.
//

extension RequestParser {
    /// Validates an HTTP/1.1 `Host = uri-host [ ":" port ]` value (RFC 9110 §7.2 / RFC 3986 §3.2.2).
    ///
    /// Rejects whitespace, `@` (userinfo spoofing), `/`, `?`, `#`, `\`, and non-numeric or `> 65535`
    /// ports. Empty `Host:` is permitted by RFC 9110 §7.2 when the target has no host.
    static func isValidHostValue(_ value: String) -> Bool {
        if value.isEmpty {
            return true
        }
        let bytes = Array(value.utf8)
        let portSlice: ArraySlice<UInt8>?
        if bytes.first == UInt8(ascii: "[") {
            guard let parsed = parseBracketedIPv6Host(bytes) else {
                return false
            }
            portSlice = parsed
        }
        else {
            guard let parsed = parseRegNameHost(bytes) else {
                return false
            }
            portSlice = parsed
        }
        return isValidOptionalPort(portSlice)
    }

    /// Validates `absolute-form` target authority against `Host` (RFC 9112 §3.2.2).
    ///
    /// When a request-target uses `http://host[:port]/...` or `https://host[:port]/...`, its
    /// authority must match `Host` (ASCII case-insensitive), rejecting proxy/origin
    /// authority-confusion smuggling. Origin-form (`/path`), asterisk-form (`*`), and
    /// authority-form (`host:port` for CONNECT) pass straight through.
    static func absoluteTargetMatchesHost(target: String, host: String) -> Bool {
        let lowerPrefix = target.prefix(8).lowercased()
        let authorityStart: String.Index
        if lowerPrefix.hasPrefix("http://") {
            authorityStart = target.index(target.startIndex, offsetBy: 7)
        }
        else if lowerPrefix.hasPrefix("https://") {
            authorityStart = target.index(target.startIndex, offsetBy: 8)
        }
        else {
            return true
        }
        let rest = target[authorityStart...]
        let authorityEnd =
            rest.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? rest.endIndex
        let targetAuthority = rest[..<authorityEnd]
        // Reject userinfo in absolute-form HTTP URIs (RFC 9110 §4.2.4) and require Host match.
        guard !targetAuthority.contains("@"), !targetAuthority.isEmpty else {
            return false
        }
        return targetAuthority.lowercased() == host.lowercased()
    }

    private static func parseBracketedIPv6Host(_ bytes: [UInt8]) -> ArraySlice<UInt8>?? {
        guard let close = bytes.firstIndex(of: UInt8(ascii: "]")), close > 1 else {
            return nil
        }
        for byte in bytes[1 ..< close] where !isIPv6LiteralByte(byte) {
            return nil
        }
        let afterClose = close + 1
        if afterClose == bytes.count {
            return .some(nil)
        }
        guard bytes[afterClose] == UInt8(ascii: ":") else {
            return nil
        }
        return .some(bytes[(afterClose + 1)...])
    }

    private static func parseRegNameHost(_ bytes: [UInt8]) -> ArraySlice<UInt8>?? {
        let hostSlice: ArraySlice<UInt8>
        let portSlice: ArraySlice<UInt8>?
        if let colon = bytes.firstIndex(of: UInt8(ascii: ":")) {
            guard !bytes[(colon + 1)...].contains(UInt8(ascii: ":")) else {
                return nil
            }
            hostSlice = bytes[..<colon]
            portSlice = bytes[(colon + 1)...]
        }
        else {
            hostSlice = bytes[...]
            portSlice = nil
        }
        guard !hostSlice.isEmpty else {
            return nil
        }
        for byte in hostSlice where !isRegNameByte(byte) {
            return nil
        }
        return .some(portSlice)
    }

    private static func isValidOptionalPort(_ port: ArraySlice<UInt8>?) -> Bool {
        guard let port, !port.isEmpty else {
            return true
        }
        guard port.count <= 5 else {
            return false
        }
        var value = 0
        for byte in port {
            guard byte >= 0x30, byte <= 0x39 else {
                return false
            }
            value = value * 10 + Int(byte - 0x30)
        }
        return value <= 65_535
    }

    private static func isIPv6LiteralByte(_ byte: UInt8) -> Bool {
        (byte >= 0x30 && byte <= 0x39)
            || (byte >= 0x41 && byte <= 0x46)
            || (byte >= 0x61 && byte <= 0x66)
            || byte == UInt8(ascii: ":")
            || byte == UInt8(ascii: ".")
    }

    private static func isRegNameByte(_ byte: UInt8) -> Bool {
        if (byte >= 0x30 && byte <= 0x39)
            || (byte >= 0x41 && byte <= 0x5A)
            || (byte >= 0x61 && byte <= 0x7A)
        {
            return true
        }
        switch byte {
            case UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"),
                UInt8(ascii: "%"), UInt8(ascii: "!"), UInt8(ascii: "$"), UInt8(ascii: "&"),
                UInt8(ascii: "'"), UInt8(ascii: "("), UInt8(ascii: ")"), UInt8(ascii: "*"),
                UInt8(ascii: "+"), UInt8(ascii: ","), UInt8(ascii: ";"), UInt8(ascii: "="):
                return true
            default:
                return false
        }
    }
}
