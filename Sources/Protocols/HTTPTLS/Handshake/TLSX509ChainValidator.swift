//
//  TLSX509ChainValidator.swift
//  HTTPTLS
//
//  The reference ``TLSClientChainValidator`` (Phase 3c): RFC 5280 §6 path validation over
//  apple/swift-certificates — chain building through the presented intermediates,
//  per-link signature checks, and `RFC5280Policy` (validity windows, basic constraints,
//  name constraints) against a PINNED anchor set (the platform trust store is never
//  consulted — the `TransportTLS.chainValidator(roots:)` contract). Trust roots are parsed
//  at CONSTRUCTION, so an undecodable or empty root set is a typed startup error, not a
//  per-handshake mystery. Rejections are classed for §6.2: no path to an anchor →
//  `unknown_ca`; a leaf outside its validity window → `certificate_expired`; the rest →
//  `bad_certificate`.
//

// swiftlint:disable sorted_imports - swift-format's OrderedImports places declaration imports last
internal import SwiftASN1
internal import X509
internal import struct Foundation.Date

// swiftlint:enable sorted_imports

/// RFC 5280 §6 client-chain validation against pinned roots, via swift-certificates.
public struct TLSX509ChainValidator: TLSClientChainValidator {
    /// A construction-time trust-root fault (fail at startup, not per handshake).
    public enum ConfigurationError: Error, Sendable, Equatable {
        /// No roots were supplied — an empty anchor set can validate nothing; requiring at
        /// least one keeps the fail-closed property visible at configuration time.
        case noTrustRoots
        /// The root at `index` is not a decodable RFC 5280 `Certificate`.
        case undecodableTrustRoot(index: Int, String)
    }

    /// The pinned anchors (RFC 5280 §6.1's trust anchor information).
    private let roots: CertificateStore
    /// When set, the leaf must also present this host in its SANs (RFC 6125 identity
    /// checking via swift-certificates' `ServerIdentityPolicy`).
    private let expectedHostname: String?

    /// Creates a validator pinned to `rootsDER` (each element one DER CA certificate).
    ///
    /// `expectedHostname` is nil by default: a client certificate names no host, so the
    /// base policy checks the path only — the `TransportTLS.chainValidator(roots:)`
    /// semantics. Set it when the deployment's clients carry host-bound certificates.
    public init(
        rootsDER: [[UInt8]], expectedHostname: String? = nil
    ) throws(ConfigurationError) {
        guard !rootsDER.isEmpty else {
            throw .noTrustRoots
        }
        var anchors: [Certificate] = []
        anchors.reserveCapacity(rootsDER.count)
        for (index, der) in rootsDER.enumerated() {
            do {
                anchors.append(try Certificate(derEncoded: der))
            }
            catch {
                throw .undecodableTrustRoot(index: index, "\(error)")
            }
        }
        roots = CertificateStore(anchors)
        self.expectedHostname = expectedHostname
    }

    /// RFC 5280 §6 path validation of the presented chain (leaf first).
    public func validate(chainDER: [[UInt8]]) async -> TLSChainVerdict {
        let chain: [Certificate]
        do {
            chain = try chainDER.map { try Certificate(derEncoded: $0) }
        }
        catch {
            return .rejected(.badCertificate("undecodable certificate: \(error)"))
        }
        guard let leaf = chain.first else {
            return .rejected(.badCertificate("empty chain"))  // unreachable via the engine
        }
        // §6.2 `certificate_expired` covers "expired or is not currently valid" — judged
        // here on the leaf so the failure classes to its own alert; an out-of-window
        // INTERMEDIATE still fails below, as the generic policy rejection.
        let now = Date()
        guard leaf.notValidBefore <= now, now <= leaf.notValidAfter else {
            return .rejected(.expired)
        }
        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy()
            if let expectedHostname {
                ServerIdentityPolicy(serverHostname: expectedHostname, serverIP: nil)
            }
        }
        let result = await verifier.validate(
            leaf: leaf, intermediates: CertificateStore(chain.dropFirst())
        )
        switch result {
            case .validCertificate:
                return .accepted
            case .couldNotValidate(let failures):
                // No candidate path even REACHED an anchor ⇒ the CA "could not be matched
                // with a known trust anchor" (§6.2 unknown_ca); a path that reached one
                // but failed policy is the generic §6.2 bad_certificate.
                guard let failure = failures.first else {
                    return .rejected(.untrustedRoot)
                }
                return .rejected(.badCertificate("\(failure.policyFailureReason)"))
        }
    }
}
