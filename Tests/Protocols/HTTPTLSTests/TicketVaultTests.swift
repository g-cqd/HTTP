//
//  TicketVaultTests.swift
//  HTTPTLSTests
//
//  The stateless vault's own contract: round trip fidelity, key rotation (old tickets stay
//  redeemable while their key stays in the ring; alien names decline), expiry, and the
//  no-oracle rule — every failure mode (truncation, bit flips anywhere, wrong AAD) is the
//  same nil, indistinguishable from an alien ticket.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("Stateless ticket vault — round trip, rotation, tamper, expiry")
struct TicketVaultTests {
    /// A deterministic sample state.
    private static func sampleState(now: UInt64) -> TLSResumptionState {
        TLSResumptionState(
            preSharedKey: SymmetricKey(data: [UInt8](repeating: 0x42, count: 32)),
            hash: .sha256,
            issuedAt: now,
            lifetimeSeconds: 600,
            ageAdd: 0xAABB_CCDD,
            serverName: "example",
            alpnProtocol: "h2"
        )
    }

    /// A vault over one named key.
    private static func makeVault(
        name: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
    ) throws -> TLSStatelessTicketVault {
        guard let key = TLSTicketKey(name: name, secret: SymmetricKey(size: .bits256)),
            let vault = TLSStatelessTicketVault(keys: [key])
        else {
            throw TLSHandshakeError.internalError("vault construction")
        }
        return vault
    }

    @Test("a sealed ticket redeems to the exact state")
    func roundTrip() throws {
        let vault = try Self.makeVault()
        let state = Self.sampleState(now: 1_000)
        let ticket = try vault.sealTicket(state)
        #expect(vault.openTicket(ticket, at: 1_100) == state)
    }

    @Test("expiry declines: at the lifetime boundary and beyond, and for future issuance")
    func expiry() throws {
        let vault = try Self.makeVault()
        let state = Self.sampleState(now: 1_000)
        let ticket = try vault.sealTicket(state)
        #expect(vault.openTicket(ticket, at: 1_599) != nil)
        #expect(vault.openTicket(ticket, at: 1_600) == nil)  // §4.6.1 lifetime is exclusive
        #expect(vault.openTicket(ticket, at: 999) == nil)  // issued "in the future"
    }

    @Test("rotation: a new sealing key redeems old tickets while the old key stays ringed")
    func rotation() throws {
        guard
            let oldKey = TLSTicketKey(
                name: [1, 1, 1, 1, 1, 1, 1, 1], secret: SymmetricKey(size: .bits256)
            ),
            let newKey = TLSTicketKey(
                name: [2, 2, 2, 2, 2, 2, 2, 2], secret: SymmetricKey(size: .bits256)
            ),
            let oldVault = TLSStatelessTicketVault(keys: [oldKey]),
            let rotated = TLSStatelessTicketVault(keys: [newKey, oldKey]),
            let retired = TLSStatelessTicketVault(keys: [newKey])
        else {
            Issue.record("vault construction failed")
            return
        }
        let state = Self.sampleState(now: 50)
        let oldTicket = try oldVault.sealTicket(state)
        #expect(rotated.openTicket(oldTicket, at: 60) == state)  // acceptance window
        #expect(retired.openTicket(oldTicket, at: 60) == nil)  // window closed
        let newTicket = try rotated.sealTicket(state)
        #expect([UInt8](newTicket[..<8]) == newKey.name)  // seals under keys.first
    }

    @Test("every single-bit flip anywhere in the ticket declines identically")
    func tamperSweep() throws {
        let vault = try Self.makeVault()
        let ticket = try vault.sealTicket(Self.sampleState(now: 10))
        for index in ticket.indices {
            var corrupted = ticket
            corrupted[index] ^= 0x01
            #expect(vault.openTicket(corrupted, at: 20) == nil, "octet \(index)")
        }
    }

    @Test("truncations decline, down to the empty ticket")
    func truncationSweep() throws {
        let vault = try Self.makeVault()
        let ticket = try vault.sealTicket(Self.sampleState(now: 10))
        for keep in 0 ..< ticket.count {
            #expect(vault.openTicket([UInt8](ticket[..<keep]), at: 20) == nil, "keep \(keep)")
        }
    }

    @Test("key material constraints: name must be 8 octets, secret 256 bits")
    func keyConstraints() {
        #expect(TLSTicketKey(name: [1, 2, 3], secret: SymmetricKey(size: .bits256)) == nil)
        #expect(
            TLSTicketKey(
                name: [1, 2, 3, 4, 5, 6, 7, 8], secret: SymmetricKey(size: .bits128)
            ) == nil
        )
        #expect(TLSStatelessTicketVault(keys: []) == nil)
    }
}
