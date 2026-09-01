//
//  ForwardedAddress.swift
//  HTTPServer
//
//  Reads the client address out of a proxy chain's `Forwarded` (RFC 7239 §4) or `X-Forwarded-For`
//  field. Both are appended to by every hop, so the entire field is client-writable when the client
//  is talking to the server directly: RFC 7239 §8.1 is explicit that a value is only as trustworthy
//  as the hop that added it. The rule this type implements is therefore the only safe one — walk the
//  chain from the right and stop at the first address that is *not* one of the operator's own proxies.
//  That address is the last hop a trusted party actually observed; everything to its left was written
//  by somebody the server has no reason to believe.
//
//  Everything fails closed. An untrusted peer means the header is ignored outright. An unparsable or
//  deliberately obfuscated node (RFC 7239 §6.3 `_hidden`, `unknown`) ends the walk with no answer,
//  rather than skipping past it into attacker-authored territory. The caller then falls back to the
//  verified transport peer, which no header can forge.
//

internal import HTTPCore
internal import HTTPTransport

/// The client address a trusted proxy chain reports (RFC 7239).
enum ForwardedAddress {
    /// The last address a trusted hop observed, or `nil` when the chain cannot be believed.
    ///
    /// Returns `nil` when `peer` is not itself inside `trusting` (the field is then attacker-authored
    /// and is ignored entirely), when every listed address is also trusted (the chain says nothing
    /// the peer did not), and when a node fails to parse. `Forwarded` wins over `X-Forwarded-For`
    /// when both are present, since it is the standardized field (RFC 7239 §1).
    static func client(_ fields: HTTPFields, peer: IPAddress, trusting: IPPrefixSet) -> IPAddress? {
        guard trusting.contains(peer) else {
            return nil
        }
        if let forwarded = fields[.forwarded] {
            return lastUntrusted(in: forValues(of: forwarded), trusting: trusting)
        }
        guard let legacy = fields[.xForwardedFor] else {
            return nil
        }
        return lastUntrusted(in: legacy.split(separator: ","), trusting: trusting)
    }

    /// Walks `nodes` right to left and returns the first address outside `trusting`.
    private static func lastUntrusted(in nodes: [Substring], trusting: IPPrefixSet) -> IPAddress? {
        for node in nodes.reversed() {
            guard let address = nodeAddress(node) else {
                return nil  // an opaque hop: the chain beyond it is unattributable
            }
            guard trusting.contains(address) else {
                return address
            }
        }
        return nil
    }

    /// The `for=` parameter values of a `Forwarded` field, in wire order (RFC 7239 §4).
    ///
    /// Elements are separated by `,` and their parameters by `;`, but a value may be a quoted-string
    /// containing either — so the scan tracks quoting rather than calling `split`.
    private static func forValues(of field: String) -> [Substring] {
        var values: [Substring] = []
        var quoted = false
        var start = field.startIndex
        var index = field.startIndex
        while index < field.endIndex {
            let character = field[index]
            if character == "\"" {
                quoted.toggle()
            }
            else if !quoted, character == "," || character == ";" {
                appendForValue(field[start ..< index], to: &values)
                start = field.index(after: index)
            }
            index = field.index(after: index)
        }
        appendForValue(field[start...], to: &values)
        return values
    }

    /// Appends the value of a `for` node to `values`, ignoring every other parameter.
    ///
    /// Parameter names are case-insensitive (RFC 7239 §4).
    private static func appendForValue(_ parameter: Substring, to values: inout [Substring]) {
        let field = trimmed(parameter)
        guard let equals = field.firstIndex(of: "=") else {
            return
        }
        let name = field[field.startIndex ..< equals]
        guard name.count == 3, name.lowercased() == "for" else {
            return
        }
        values.append(trimmed(field[field.index(after: equals)...]))
    }

    /// The address in one node value: unquoted, unbracketed, and stripped of any port.
    ///
    /// RFC 7239 §6 allows `for="[2001:db8::1]:4711"` and `for=192.0.2.1:4711`; an obfuscated
    /// identifier or `unknown` simply fails to parse, which is what ends the walk.
    private static func nodeAddress(_ node: Substring) -> IPAddress? {
        var text = trimmed(node)
        if text.count >= 2, text.first == "\"", text.last == "\"" {
            text = trimmed(text.dropFirst().dropLast())
        }
        guard text.first != "[" else {
            guard let closing = text.firstIndex(of: "]") else {
                return nil
            }
            let remainder = text[text.index(after: closing)...]
            guard remainder.isEmpty || remainder.first == ":" else {
                return nil
            }
            return IPAddress(text[text.index(after: text.startIndex) ..< closing])
        }
        // A bare IPv6 literal is full of colons; only a single colon can be a port separator.
        guard let colon = text.firstIndex(of: ":"),
            !text[text.index(after: colon)...].contains(":")
        else {
            return IPAddress(text)
        }
        return IPAddress(text[text.startIndex ..< colon])
    }

    /// `text` without leading or trailing RFC 9110 §5.6.3 optional whitespace.
    private static func trimmed(_ text: Substring) -> Substring {
        var slice = text
        while let first = slice.first, first == " " || first == "\t" {
            slice = slice.dropFirst()
        }
        while let last = slice.last, last == " " || last == "\t" {
            slice = slice.dropLast()
        }
        return slice
    }
}
