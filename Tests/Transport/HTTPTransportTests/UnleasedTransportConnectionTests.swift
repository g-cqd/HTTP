//
//  UnleasedTransportConnectionTests.swift
//  HTTPTransportTests
//
//  Audit F-03, the inherited half: WHICH backbones are allowed to compose a logical I/O operation out
//  of several gated calls.
//
//  Two ``TransportConnection`` defaults did that — the appending `receive(into:maxLength:)` and the
//  chunked `sendFile` — and both were inheritable by anything. That is the third and fourth appearance
//  of the release-then-continue shape in this subsystem: portable TLS `receive` and
//  `POSIXKqueueConnection` were live defects and were fixed one site at a time, and the shape stayed
//  available. It was collected once more the week this was written, when ``PortableTLSConnection``
//  turned out to be inheriting the chunked `sendFile` and releasing its outbound lease per 64 KiB
//  chunk. Fixing that instance and leaving the default inheritable would have been fixing the fourth
//  occurrence and shipping the fifth.
//
//  So the defaults moved onto ``UnleasedTransportConnection``, and the PRIMARY check is the compiler:
//  a backbone that states nothing no longer gets a silently narrowed ownership span, it gets an error
//  naming the requirement. That check cannot be written as a test — a compile failure is not a test
//  case — so this suite is the runtime half, and it checks the thing the compiler cannot: that the
//  conformance is TRUE. `UnleasedTransportConnection` is a waiver, and a waiver signed by a type that
//  does lease a direction would be worse than no waiver at all, because it would look enforced.
//
//  PORTABLE ON PURPOSE, like `ConnectionDirectionOwnershipTests`: the list below is assembled by `#if`
//  so it audits whichever backbones the platform actually builds, rather than reading as full coverage
//  on Darwin and silently auditing nothing on Linux.
//
//  Standards: CWE-1188 (insecure default initialization of a resource) — a default whose correctness
//  depends on a property of the conformer that nothing checks. TCP's one sequence space per direction
//  (RFC 9293 §3.1) is the reason a direction has one owner at all.
//

import HTTPTestSupport
import Testing

@testable import HTTPTransport

@Suite("Transport — who may inherit the unleased I/O defaults (audit F-03)")
struct UnleasedTransportConnectionTests {
    /// One conformer, and the two facts about it that must agree.
    struct AuditedConformer: Sendable, CustomStringConvertible {
        let name: String
        /// Whether the type serializes at least one direction ACROSS a suspension point — a
        /// ``DirectionOwner``, or an `AsyncExclusion` held over a readiness park.
        let leasesADirection: Bool
        /// Whether the type conforms to ``UnleasedTransportConnection``.
        let inheritsTheAdapters: Bool

        var description: String { name }
    }

    /// Audits one conformer, resolving its conformance through a GENERIC parameter.
    ///
    /// The indirection is deliberate. Spelled concretely the compiler folds the check and rejects it
    /// — `error: 'is' test is always true` — which is worth knowing (the conformance is statically
    /// decidable, so the compiler really is the primary check) but leaves this suite asserting a
    /// constant. Through a generic parameter it is a real runtime conformance lookup, so granting a
    /// leased backbone the waiver FAILS this suite instead of folding to a different constant.
    ///
    /// The name is derived from the metatype rather than passed in, so it cannot drift from the type
    /// it labels when a backbone is renamed.
    static func audit<Connection: TransportConnection>(
        _ type: Connection.Type,
        leasesADirection: Bool
    ) -> AuditedConformer {
        AuditedConformer(
            name: "\(type)",
            leasesADirection: leasesADirection,
            inheritsTheAdapters: type is any UnleasedTransportConnection.Type
        )
    }

    /// Every ``TransportConnection`` conformer this platform builds, with its lease ownership stated.
    ///
    /// Adding a backbone here is the point: a new one that is not listed is not audited, and the list
    /// is short enough that omitting one is visible in review.
    static let audited: [AuditedConformer] = {
        var conformers = [
            audit(FakeConnection.self, leasesADirection: false),
            audit(DribblingConnection.self, leasesADirection: false),
            audit(HangingConnection.self, leasesADirection: false),
            audit(SynthesizedUploadConnection.self, leasesADirection: false)
        ]
        #if canImport(Darwin)
            conformers += [
                audit(NetworkFrameworkConnection.self, leasesADirection: false),
                audit(POSIXKqueueConnection.self, leasesADirection: true),
                audit(POSIXDispatchConnection.self, leasesADirection: true),
                audit(SwiftSystemConnection.self, leasesADirection: true)
            ]
        #endif
        #if canImport(Glibc)
            conformers.append(audit(POSIXEpollConnection.self, leasesADirection: true))
        #endif
        #if canImport(CHTTPBoringSSLShims)
            conformers.append(audit(PortableTLSConnection.self, leasesADirection: true))
        #endif
        return conformers
    }()

    /// A backbone inherits the adapting defaults exactly when it has no lease for them to drop.
    ///
    /// Both directions of this matter, and each catches a different mistake. A leased backbone that
    /// conformed would silently re-acquire a per-chunk `sendFile` and a copy-out outside its own
    /// receive lease — the two defects this audit found — while looking like it had opted in
    /// deliberately. An unleased backbone that did NOT conform would have to hand-roll both adapters,
    /// which is how three subtly different copies of a fail-closed short-read check appear.
    @Test(
        "a backbone inherits the unleased defaults exactly when it leases no direction",
        arguments: audited)
    func adapterInheritanceMatchesLeaseOwnership(_ conformer: AuditedConformer) {
        #expect(
            conformer.inheritsTheAdapters == !conformer.leasesADirection,
            conformer.leasesADirection
                ? """
                \(conformer.name) leases a direction and must not inherit the unleased defaults: \
                the chunked sendFile would release that lease once per chunk, and the appending \
                receive would put the copy-out outside it
                """
                : """
                \(conformer.name) leases nothing, so it should take the shared adapters rather than \
                carry its own copy of the fail-closed short-read check
                """
        )
    }

    /// The retained receive adapter still appends in order and reports what it appended.
    ///
    /// Characterization, not aspiration: moving a default between protocols must not change what it
    /// does, and the only way to say that is to pin the behaviour on both sides of the move.
    @Test("the inherited receive adapter appends each chunk in stream order")
    func theReceiveAdapterAppendsInStreamOrder() async throws {
        let payload = Array("the quick brown fox".utf8)
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: payload)
        var buffer = Array("sentinel-".utf8)
        var appended = 0
        while true {
            let count = try await connection.receive(into: &buffer, maxLength: 4)
            guard count > 0 else {
                break
            }
            appended += count
        }
        #expect(appended == payload.count)
        #expect(buffer == Array("sentinel-".utf8) + payload)
    }

    /// A receive that finds end of stream reports zero and leaves the buffer byte-for-byte alone.
    ///
    /// The sentinel is the claim: "appended nothing" has to mean the accumulator is untouched, not
    /// merely that its count is unchanged.
    @Test("the inherited receive adapter leaves the buffer untouched at end of stream")
    func theReceiveAdapterAppendsNothingAtEndOfStream() async throws {
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: [])
        let sentinel = Array("untouched".utf8)
        var buffer = sentinel
        for _ in 0 ..< 3 {
            #expect(try await connection.receive(into: &buffer, maxLength: 4_096) == 0)
            #expect(buffer == sentinel)
        }
    }
}
