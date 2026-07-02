//
//  TLSPeerIdentity.swift
//  HTTPTransport
//
//  The verified client-certificate identity captured at the TLS handshake (mutual TLS, RFC 8446
//  §4.4.2) — the G3 follow-up widening the header-era leaf-subject string into the full, typed
//  identity: the DER chain, the leaf subject summary, and the leaf's Subject Alternative Names
//  (RFC 5280 §4.2.1.6). Server-asserted (captured from the handshake, never from a client-supplied
//  header), so a peer cannot spoof any of it.
//

/// The peer's verified client-certificate identity (mutual TLS), captured once the handshake settles.
///
/// Carried by ``TransportConnection/tlsPeerIdentity`` (and its QUIC twin) and surfaced to handlers as
/// request-scoped context, so an application can authorize on more than the leaf subject string: pin
/// the exact leaf, walk the presented chain, or match a SAN. All fields describe the *verified*
/// handshake result — the chain the transport's `verifyPeer` policy admitted.
public struct TLSPeerIdentity: Sendable, Hashable {
    /// The peer's DER-encoded certificate chain, leaf first (RFC 5280), exactly as presented in the
    /// handshake.
    public var chainDER: [[UInt8]]

    /// The leaf certificate's subject summary (typically its Common Name), or `nil` when the backbone
    /// could not derive one — the value historically exposed alone as `tlsPeerSubject`.
    public var subject: String?

    /// The leaf certificate's Subject Alternative Names (RFC 5280 §4.2.1.6).
    ///
    /// DNS names, IP addresses, email addresses, and URIs; empty when the leaf carries no SAN
    /// extension.
    public var subjectAlternativeNames: [SubjectAlternativeName]

    /// The leaf certificate's raw DER bytes (the first chain element), or `nil` for an empty chain.
    public var leafDER: [UInt8]? { chainDER.first }

    /// Creates an identity from its parts.
    public init(
        chainDER: [[UInt8]],
        subject: String? = nil,
        subjectAlternativeNames: [SubjectAlternativeName] = []
    ) {
        self.chainDER = chainDER
        self.subject = subject
        self.subjectAlternativeNames = subjectAlternativeNames
    }

    /// Creates an identity from a presented DER chain, extracting the leaf's Subject Alternative
    /// Names from its DER encoding (RFC 5280 §4.2.1.6) — the form the TLS backbones build once per
    /// handshake, off the byte path.
    public init(chainDER: [[UInt8]], subject: String?) {
        self.init(
            chainDER: chainDER,
            subject: subject,
            subjectAlternativeNames: chainDER.first
                .map(X509SubjectAlternativeNames.extract) ?? []
        )
    }
}
