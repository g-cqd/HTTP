//
//  TraceEntropy.swift
//  HTTPTLSTests
//
//  The RFC 8448 injection seam in action: fixed server random + the trace's PUBLISHED server
//  ephemeral private key, so the machine's ServerHello, shared secret, and every derived
//  secret land byte-exactly on the trace. Test-only by construction — production code never
//  sees this type; it sees ``TLSServerEntropy``.
//

internal import HTTPTLS

/// Deterministic entropy replaying an RFC 8448 trace's published values.
struct TraceEntropy: TLSServerEntropy {
    /// The trace's ServerHello random (32 octets).
    let random: [UInt8]
    /// The trace's ephemeral private key for the group under test.
    let privateKey: [UInt8]
    /// A fixed §4.6.1 `ticket_age_add`.
    let ageAdd: UInt32

    /// Creates trace entropy from published values.
    init(random: [UInt8], privateKey: [UInt8], ageAdd: UInt32 = 0x0102_0304) {
        self.random = random
        self.privateKey = privateKey
        self.ageAdd = ageAdd
    }

    /// The fixed server random.
    func serverRandom() -> [UInt8] {
        random
    }

    /// The fixed ephemeral, whatever the group (each trace uses exactly one).
    func ephemeralPrivateKey(for _: TLSNamedGroup) -> [UInt8] {
        privateKey
    }

    /// The fixed `ticket_age_add`.
    func ticketAgeAdd() -> UInt32 {
        ageAdd
    }
}
