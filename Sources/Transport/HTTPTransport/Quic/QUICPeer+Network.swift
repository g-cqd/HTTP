//
//  QUICPeer+Network.swift
//  HTTPTransport
//
//  The Network.framework half of ``QUICPeer``: turning whatever remote endpoint Network.framework
//  reports for an inbound QUIC connection into the ``TransportAddress`` the admission gate charges.
//
//  Split from `QUICPeer.swift` so that `internal import Network` — and therefore this file — is the
//  only part of QUIC peer attribution the Linux build has to drop. The sentinel this maps onto,
//  ``QUICPeer/unattributed``, stays platform-neutral next door because it is the admission contract
//  rather than a detail of the transport that happens to produce it. Listed in the manifest's
//  `darwinOnlyTransportSources` alongside the two QUIC backbones that are its only callers.
//

internal import Network

extension QUICPeer {
    /// `endpoint` as a peer address, or ``QUICPeer/unattributed`` when it carries no host and port.
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
