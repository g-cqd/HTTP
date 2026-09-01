//
//  IPPrefixTests.swift
//  HTTPTransportTests
//
//  ``IPAddress``, ``IPPrefix`` and ``IPPrefixSet``: strict literal parsing (RFC 791 §3.1, RFC 4291
//  §2.2), canonical text (RFC 5952 §4), masking, and CIDR membership at the /0, /32 and /128
//  boundaries. The malformed vectors are the point of the suite: a parser that accepts `0177.0.0.1`
//  or a zone identifier disagrees with the socket about which host it is looking at, and an allow or
//  trust decision built on that disagreement is a bypass (CVE-2021-29662, CWE-1289).
//

import HTTPTransport
import Testing

/// Literal → the canonical text it must normalize to.
private let validAddresses: [(literal: String, canonical: String)] = [
    ("0.0.0.0", "0.0.0.0"),
    ("127.0.0.1", "127.0.0.1"),
    ("255.255.255.255", "255.255.255.255"),
    ("10.0.0.1", "10.0.0.1"),
    ("::", "::"),
    ("::1", "::1"),
    ("[::1]", "::1"),
    ("1::", "1::"),
    ("2001:db8::1", "2001:db8::1"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("2001:DB8::1", "2001:db8::1"),
    ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
    ("[2001:db8::1]", "2001:db8::1"),
    // RFC 5952 §4.2.3: the *longest* zero run compresses, leftmost on a tie.
    ("0:0:0:1:0:0:0:0", "0:0:0:1::"),
    ("1:0:0:2:0:0:3:4", "1::2:0:0:3:4"),
    // RFC 4291 §2.5.5.2: the IPv4-mapped form folds onto v4, so one host has one identity.
    ("::ffff:192.0.2.1", "192.0.2.1"),
    ("::ffff:0:0", "0.0.0.0")
]

/// Inputs that must not parse.
private let malformedAddresses: [String] = [
    "",
    " ",
    "10.0.0",
    "10.0.0.1.2",
    "10.0.0.256",
    "0177.0.0.1",  // octal-looking: a permissive parser reads 127.0.0.1 (CWE-1289)
    "010.0.0.1",
    "10.0.0.01",
    "10.0.0.-1",
    "10.0.0.1 ",
    "1.2.3.4:80",  // an authority, not an address
    "fe80::1%en0",  // a zone identifier (RFC 4007 §11)
    ":",
    ":1",
    "1:",
    ":::",
    "1:::2",
    "1::2::3",
    "1:2:3:4:5:6:7:8:9",
    "1:2:3:4:5:6:7",
    "12345::",
    "::gggg",
    "[::1",
    "::1]",
    "[::1]x",
    "1.2.3.4:5",
    "::1.2.3.4:5",
    "1:2:3:4:5:1.2.3.4:8",  // a dotted quad that is not the last token
    "example.com",
    "localhost"
]

/// CIDR block → an address inside it → an address outside it.
private let membershipVectors: [(cidr: String, inside: String, outside: String)] = [
    ("0.0.0.0/0", "203.0.113.9", "::1"),
    ("::/0", "2001:db8::1", "203.0.113.9"),
    ("10.0.0.0/8", "10.255.255.255", "11.0.0.1"),
    ("172.16.0.0/12", "172.31.255.255", "172.32.0.1"),
    ("192.168.0.0/16", "192.168.255.1", "192.169.0.1"),
    ("100.64.0.0/10", "100.127.255.255", "100.128.0.1"),
    ("203.0.113.7/32", "203.0.113.7", "203.0.113.8"),
    ("::1/128", "::1", "::2"),
    ("2001:db8::/32", "2001:db8:ffff::1", "2001:db9::1"),
    ("2001:db8:0:1::/64", "2001:db8:0:1:ffff::1", "2001:db8:0:2::1"),
    ("fc00::/7", "fdff::1", "fe00::1"),
    ("fe80::/10", "febf::1", "fec0::1")
]

/// Inputs that must not parse as a CIDR block.
private let malformedPrefixes: [String] = [
    "10.0.0.0",
    "10.0.0.0/",
    "10.0.0.0/8/8",
    "10.0.0.0/33",
    "10.0.0.0/-1",
    "10.0.0.0/ 8",
    "10.0.0.0/008",
    "::1/129",
    "::1/1000",
    "/8",
    "notanaddress/8"
]

@Test("parses a literal and normalizes it to canonical text", arguments: validAddresses)
func parsesAndCanonicalizes(literal: String, canonical: String) {
    let address = IPAddress(literal)
    #expect(address != nil)
    #expect(address?.canonicalText == canonical)
}

@Test("canonical text round-trips through the parser", arguments: validAddresses)
func canonicalTextRoundTrips(literal: String, canonical: String) {
    guard let address = IPAddress(literal) else {
        Issue.record("\(literal) did not parse")
        return
    }
    #expect(IPAddress(address.canonicalText) == address)
    #expect(IPAddress(canonical) == address)
}

@Test("rejects a malformed or ambiguous literal", arguments: malformedAddresses)
func rejectsMalformedLiterals(literal: String) {
    #expect(IPAddress(literal) == nil)
}

@Test("a prefix contains its own members and nothing outside", arguments: membershipVectors)
func prefixMembership(cidr: String, inside: String, outside: String) {
    guard let prefix = IPPrefix(cidr), let member = IPAddress(inside),
        let stranger = IPAddress(outside)
    else {
        Issue.record("\(cidr) / \(inside) / \(outside) did not parse")
        return
    }
    #expect(prefix.contains(member))
    #expect(!prefix.contains(stranger))
}

@Test("rejects a malformed CIDR block", arguments: malformedPrefixes)
func rejectsMalformedPrefixes(cidr: String) {
    #expect(IPPrefix(cidr) == nil)
}

@Test("a prefix masks its host bits away, so 10.1.2.3/8 is 10.0.0.0/8")
func prefixNormalizesItsAddress() {
    #expect(IPPrefix("10.1.2.3/8") == IPPrefix("10.0.0.0/8"))
    #expect(IPPrefix("10.1.2.3/8")?.address == IPAddress("10.0.0.0"))
    #expect(IPPrefix("2001:db8:1:2:3:4:5:6/64") == IPPrefix("2001:db8:1:2::/64"))
}

@Test("a prefix never contains an address of the other family")
func prefixIsFamilyScoped() {
    #expect(IPPrefix("0.0.0.0/0")?.contains(IPAddress("::") ?? .v4(0)) == false)
    #expect(IPPrefix("::/0")?.contains(IPAddress("0.0.0.0") ?? .v4(0)) == false)
}

@Test("masking to the family width is the identity, and to zero bits erases everything")
func maskingBoundaries() {
    #expect(IPAddress("203.0.113.9")?.masked(to: 32) == IPAddress("203.0.113.9"))
    #expect(IPAddress("203.0.113.9")?.masked(to: 0) == IPAddress("0.0.0.0"))
    #expect(IPAddress("203.0.113.9")?.masked(to: 24) == IPAddress("203.0.113.0"))
    #expect(IPAddress("2001:db8::1")?.masked(to: 128) == IPAddress("2001:db8::1"))
    #expect(IPAddress("2001:db8::1")?.masked(to: 0) == IPAddress("::"))
    #expect(IPAddress("2001:db8:1:2:3:4:5:6")?.masked(to: 64) == IPAddress("2001:db8:1:2::"))
    #expect(IPAddress("2001:db8:1:2:3:4:5:6")?.masked(to: 65) == IPAddress("2001:db8:1:2::"))
    #expect(IPAddress("2001:db8:1:2:8000::")?.masked(to: 65) == IPAddress("2001:db8:1:2:8000::"))
}

@Test("the shipped prefix sets cover their RFC blocks")
func shippedSets() {
    #expect(IPPrefixSet.none.isEmpty)
    #expect(IPPrefixSet.none.contains(IPAddress("127.0.0.1") ?? .v4(0)) == false)
    #expect(IPPrefixSet.loopback.contains(IPAddress("127.0.0.1") ?? .v4(0)))
    #expect(IPPrefixSet.loopback.contains(IPAddress("127.255.255.254") ?? .v4(0)))
    #expect(IPPrefixSet.loopback.contains(IPAddress("::1") ?? .v4(0)))
    #expect(IPPrefixSet.loopback.contains(IPAddress("10.0.0.1") ?? .v4(0)) == false)
    #expect(IPPrefixSet.privateUse.contains(IPAddress("10.0.0.1") ?? .v4(0)))
    #expect(IPPrefixSet.privateUse.contains(IPAddress("192.168.1.1") ?? .v4(0)))
    #expect(IPPrefixSet.privateUse.contains(IPAddress("fd00::1") ?? .v4(0)))
    #expect(IPPrefixSet.privateUse.contains(IPAddress("203.0.113.9") ?? .v4(0)) == false)
    #expect(IPPrefixSet.privateUse.contains(IPAddress("127.0.0.1") ?? .v4(0)) == false)
    #expect(IPPrefixSet.privateUse.union(.loopback).contains(IPAddress("127.0.0.1") ?? .v4(0)))
}

@Test("a set of CIDR strings parses all-or-nothing")
func setParsesAllOrNothing() {
    #expect(IPPrefixSet(cidrs: ["10.0.0.0/8", "::1/128"])?.prefixes.count == 2)
    #expect(IPPrefixSet(cidrs: ["10.0.0.0/8", "nonsense"]) == nil)
    #expect(IPPrefixSet(cidrs: [])?.isEmpty == true)
}

@Test("a transport address exposes its host as a parsed literal, and never resolves a name")
func transportAddressExposesItsLiteral() {
    #expect(TransportAddress(host: "203.0.113.9", port: 443).ipAddress == IPAddress("203.0.113.9"))
    #expect(TransportAddress(host: "::1", port: 443).ipAddress == IPAddress("::1"))
    #expect(TransportAddress(host: "example.com", port: 443).ipAddress == nil)
}
