//
//  QUICPeerAdmissionTests.swift
//  HTTPTransportTests
//
//  The platform-neutral half of QUIC peer attribution: what ``QUICPeer/unattributed`` promises the
//  admission gate, independent of which backbone produced it.
//
//  Split out of `QUICPeerAttributionTests` — which needs Network.framework listeners and real h3
//  clients, and is therefore excluded from the Linux build with the QUIC backbones themselves — so
//  that the ADD-P0.5b contract does not leave the Linux graph along with the transport. The claim
//  under test is not "Network.framework reports the right endpoint" but "a connection nobody could
//  attribute is charged to one shared, capped, unforgeable bucket", and that claim is about
//  ``ConnectionAdmission`` and a sentinel `TransportAddress`. Both are portable, so the coverage
//  should be too.
//
//  Standards: the per-host ceiling is a resource-exhaustion defense — CWE-770 (allocation without
//  limits), CWE-400 (uncontrolled resource consumption). QUIC connections are per-peer (RFC 9000
//  §5.1).
//

import HTTPTestSupport
import Testing

@testable import HTTPTransport

@Suite("QUIC peer attribution — the platform-neutral admission contract")
struct QUICPeerAdmissionTests {
    /// The sentinel must not be mistakable for an address the server actually verified.
    ///
    /// `ipAddress == nil` is the load-bearing one: it is what makes `RateLimitIdentity.peerAddress`
    /// fold an unattributable peer into the shared fail-closed budget rather than treating `"-"` as a
    /// host it can trust.
    @Test("the unattributed sentinel is not mistakable for a verified address")
    func sentinelIsNotAParseableAddress() {
        #expect(QUICPeer.unattributed.ipAddress == nil)
        #expect(QUICPeer.unattributed.host == "-")
        #expect(QUICPeer.unattributed.port == 0)
    }

    /// Every unattributable connection lands in ONE per-host bucket, not one bucket each.
    ///
    /// The inverse — a distinct bucket per unattributable peer — is precisely the CWE-770 hole the
    /// sentinel exists to close, because a peer the server cannot name could then mint unlimited
    /// buckets and the per-client ceiling would bound nothing.
    @Test(
        "unattributable peers share one admission bucket rather than escaping the cap",
        arguments: [2, 8, 64]
    )
    func unattributablePeersShareOneBucket(peerCount: Int) {
        let admission = ConnectionAdmission(
            capacity: ConnectionAdmission.Capacity(total: peerCount * 2, perHost: peerCount * 2)
        )
        // Held for the duration: a released `AdmissionTicket` returns its slot in `deinit`, so
        // dropping these would unwind the very counts under assertion.
        let tickets = (0 ..< peerCount)
            .map { _ in
                admission.admit(host: QUICPeer.unattributed.host)
            }
        #expect(admission.counts == (total: peerCount, hosts: 1))
        _ = tickets
    }

    /// Sharing one bucket is only a defense if that bucket is actually CAPPED.
    ///
    /// Asserted as a `rejectedHost` rather than a count, because the distinction matters to the
    /// transport: a host rejection must leave the accept source draining, so one unattributable flood
    /// cannot deny service to the peers the server *can* name.
    @Test(
        "the shared bucket is bound by the per-host ceiling like any other host",
        arguments: [1, 4, 16]
    )
    func unattributableBucketIsCapped(perHost: Int) {
        let admission = ConnectionAdmission(
            capacity: ConnectionAdmission.Capacity(total: 1_000, perHost: perHost)
        )
        let tickets = (0 ..< perHost)
            .map { _ in
                admission.admit(host: QUICPeer.unattributed.host)
            }
        #expect(admission.admit(host: QUICPeer.unattributed.host) == .rejectedHost)
        #expect(admission.counts == (total: perHost, hosts: 1))
        _ = tickets
    }
}
