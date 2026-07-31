//
//  QUICPeer.swift
//  HTTPTransport
//
//  Peer attribution for the QUIC backbones: turning whatever remote endpoint Network.framework
//  reports for an inbound QUIC connection into the ``TransportAddress`` the admission gate charges
//  and ``QUICConnection/peer`` publishes.
//
//  This exists because the two backbones read the peer from two different (and, in both cases,
//  undocumented-for-inbound) places, and because the failure mode when neither yields an address
//  must be a deliberate, shared one rather than a plausible-looking lie. Both backbones previously
//  reported the listener's own bind address, which is worse than reporting nothing: every HTTP/3
//  client then hashed to one per-host bucket, so `maxConnectionsPerClient` silently degenerated into
//  a global HTTP/3 cap and stopped isolating clients from one another (CWE-770).
//
//  Standards: QUIC connections are per-peer (RFC 9000 §5.1); the per-host ceiling is a
//  resource-exhaustion defense (CWE-770, CWE-400).
//

internal import Network

/// How a QUIC backbone names the peer of an inbound connection (RFC 9000 §5.1).
public enum QUICPeer {
    /// The address used when Network.framework reports no host/port for a connection's peer.
    ///
    /// Deliberately **not** a parseable IP literal, so ``TransportAddress/ipAddress`` is `nil` and
    /// `RateLimitIdentity.peerAddress` folds it into the one shared, fail-closed budget it already
    /// reserves for a request whose provenance is unknown — the same `"-"` convention, not a second
    /// one. Every unattributable connection therefore shares a single per-host admission bucket:
    /// conservative (they cannot exceed the per-client ceiling between them) and honest (nothing
    /// downstream can mistake it for a verified address).
    public static let unattributed = TransportAddress(host: "-", port: 0)

    /// `endpoint` as a peer address, or ``unattributed`` when it carries no host and port.
    ///
    /// Host/port endpoints are parsed exactly as the TCP Network.framework backbone parses them, so
    /// an h3 peer and an h1/h2 peer from the same client produce the same budget key. Every other
    /// endpoint shape (and `nil`) is unattributable rather than stringified: a service name or a
    /// socket path is not a peer address, and pretending otherwise would key a rate-limit budget on
    /// something the server never verified.
    static func address(of endpoint: NWEndpoint?) -> TransportAddress {
        guard let endpoint, case .hostPort = endpoint else {
            return unattributed
        }
        return NetworkFrameworkConnection.address(of: endpoint)
    }
}
