//
//  SubjectAlternativeName.swift
//  HTTPTransport
//
//  One Subject Alternative Name entry from an X.509 certificate (RFC 5280 §4.2.1.6) — the typed
//  form of the GeneralName variants a client certificate identifies itself with. Only the four
//  name forms that identify a network peer are modeled; the exotic forms (otherName, x400Address,
//  directoryName, ediPartyName, registeredID) are skipped by the extractor rather than stringified
//  lossily.
//

/// One Subject Alternative Name of an X.509 certificate (RFC 5280 §4.2.1.6).
public enum SubjectAlternativeName: Sendable, Hashable {
    /// A `dNSName` entry (an IA5String host name).
    case dns(String)

    /// An `iPAddress` entry, rendered as dotted-quad IPv4 (RFC 791) or colon-grouped IPv6
    /// (RFC 4291 §2.2 form 1 — full groups, no zero compression).
    case ip(String)

    /// An `rfc822Name` entry (an email address).
    case email(String)

    /// A `uniformResourceIdentifier` entry.
    case uri(String)
}
