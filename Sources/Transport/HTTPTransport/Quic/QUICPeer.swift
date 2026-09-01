//
//  QUICPeer.swift
//  HTTPTransport
//
//  Peer attribution for the QUIC backbones: the ``TransportAddress`` the admission gate charges and
//  ``QUICConnection/peer`` publishes for an inbound QUIC connection.
//
//  This exists because the two backbones read the peer from two different (and, in both cases,
//  undocumented-for-inbound) places, and because the failure mode when neither yields an address
//  must be a deliberate, shared one rather than a plausible-looking lie. Both backbones previously
//  reported the listener's own bind address, which is worse than reporting nothing: every HTTP/3
//  client then hashed to one per-host bucket, so `maxConnectionsPerClient` silently degenerated into
//  a global HTTP/3 cap and stopped isolating clients from one another (CWE-770).
//
//  This file is the platform-NEUTRAL half, and the split is deliberate. The sentinel below is the
//  admission/rate-limit contract itself (ADD-P0.5b) — it is asserted by `HTTP3RateLimitIdentityTests`
//  in the server target, which has no Darwin dependency and must keep running on Linux. Only the
//  mapping FROM a Network.framework endpoint is Darwin-specific, and it lives in
//  `QUICPeer+Network.swift`, which the manifest excludes on Linux with the rest of the
//  Network.framework backbone. Keeping `unattributed` here means a Linux build that has no QUIC
//  backbone at all still compiles, and still tests, the fail-closed budget every unattributable
//  peer folds into — rather than losing the contract along with the transport.
//
//  Standards: QUIC connections are per-peer (RFC 9000 §5.1); the per-host ceiling is a
//  resource-exhaustion defense (CWE-770, CWE-400).
//

/// How a QUIC backbone names the peer of an inbound connection (RFC 9000 §5.1).
public enum QUICPeer {
    /// The address used when a QUIC backbone reports no host/port for a connection's peer.
    ///
    /// Deliberately **not** a parseable IP literal, so ``TransportAddress/ipAddress`` is `nil` and
    /// `RateLimitIdentity.peerAddress` folds it into the one shared, fail-closed budget it already
    /// reserves for a request whose provenance is unknown — the same `"-"` convention, not a second
    /// one. Every unattributable connection therefore shares a single per-host admission bucket:
    /// conservative (they cannot exceed the per-client ceiling between them) and honest (nothing
    /// downstream can mistake it for a verified address).
    public static let unattributed = TransportAddress(host: "-", port: 0)
}
