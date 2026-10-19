//
//  BasicAuthAllocationTests.swift
//  HTTPAuthTests
//
//  The direct regression for the fixed-credential precompute. The blinding `SymmetricKey` and the two
//  expected tags belong to the middleware instance, not to the request: generating a fresh 256-bit key
//  inside the comparison means every authenticated request pays two key generations (each drawing from
//  the CSPRNG into a fresh locked buffer) plus four HMACs, when two HMACs suffice. This pins the
//  allocation floor of one verification so re-introducing a per-request key trips immediately.
//
//  Also pins the timing property the blinded comparison exists for (CWE-208, observable timing
//  discrepancy): both comparisons must run whatever the outcome, so a wrong username and a wrong
//  password are indistinguishable. `&&` short-circuits the branch, not the two `let`s above it.
//

import HTTPTestSupport
import Testing

@testable import HTTPAuth

@Suite("HTTPAuth — Basic-auth fixed-credential verification cost (CWE-208)")
struct BasicAuthAllocationTests {
    private static let verify = BasicAuthMiddleware.fixedCredentialVerifier("alice", "s3cret")

    /// One verification, in allocations: above the 16-24 two precomputed HMACs cost, below the 34 a fresh
    /// key per request cost.
    private static let allocationCeiling = 28

    @Test("verifying a credential allocates no per-request symmetric key")
    func verificationDoesNotAllocateAKey() {
        // Warm up so one-time lazy initialization is not charged to the measured run.
        #expect(Self.verify("alice", "s3cret"))
        // Measured: 16 on macOS 27 and 24 on the macOS 26 CI runner (swift-crypto 5.0.1, debug and release
        // alike; the platform crypto backend differs) — two HMACs, each costing a `Data(candidate.utf8)`
        // copy for swift-crypto's `DataProtocol` entry point plus its own digest/context buffers. Before the
        // precompute this was 34: two `SymmetricKey(size: .bits256)` generations and four HMACs. The ceiling
        // of 28 clears the slower platform with room while staying under 34, so a re-introduced per-request
        // key trips it and an OS difference does not.
        _ = expectAllocations(noMoreThan: Self.allocationCeiling) {
            _ = Self.verify("alice", "s3cret")
        }
    }

    @Test(
        "a rejection costs the same as an acceptance — no early exit on the username",
        arguments: [
            (user: "alice", password: "s3cret", expected: true),
            (user: "alice", password: "wrong", expected: false),
            (user: "mallory", password: "s3cret", expected: false),
            (user: "mallory", password: "wrong", expected: false),
            (user: "", password: "", expected: false)
        ]
    )
    func bothComparisonsAlwaysRun(credential: (user: String, password: String, expected: Bool)) {
        #expect(Self.verify(credential.user, credential.password) == credential.expected)
        _ = expectAllocations(noMoreThan: Self.allocationCeiling) {
            _ = Self.verify(credential.user, credential.password)
        }
    }
}
