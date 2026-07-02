//
//  SecurityChainValidator.swift
//  HTTPTransport
//
//  The Darwin implementation of the trust-roots `verifyPeer` seam (G3): X.509 path validation
//  (RFC 5280 §6) of a presented client-certificate chain against a fixed set of root CAs, via the
//  Security framework's `SecTrust` — anchors pinned to exactly the given roots (system roots
//  excluded), basic X.509 policy (chain building, signatures, validity windows; no host-name or EKU
//  semantics — a client certificate names no host). Runs once per handshake, never on the byte path.
//
//  Gated `#if canImport(Security)` — the portable (BoringSSL) twin covers Linux.
//

#if canImport(Security)

    internal import Foundation
    internal import Security

    /// Validates presented DER chains against pinned root CAs with `SecTrust` (RFC 5280 §6).
    enum SecurityChainValidator {
        /// A `verifyPeer` hook accepting only chains that validate to one of `roots` (DER).
        ///
        /// Fails closed: an empty chain, an undecodable certificate, or any `SecTrust` refusal is a
        /// rejection.
        static func validator(roots: [[UInt8]]) -> @Sendable ([[UInt8]]) -> Bool {
            { chainDER in
                guard !chainDER.isEmpty, !roots.isEmpty,
                    let chain = certificates(chainDER),
                    let anchors = certificates(roots)
                else {
                    return false
                }
                var rawTrust: SecTrust?
                let created = SecTrustCreateWithCertificates(
                    chain as CFArray, SecPolicyCreateBasicX509(), &rawTrust
                )
                guard created == errSecSuccess, let trust = rawTrust else {
                    return false
                }
                // Pin the anchor set to exactly the given roots — the system trust store must NOT
                // admit a chain these roots do not (that would silently widen the policy).
                guard
                    SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
                    SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess
                else {
                    return false
                }
                return SecTrustEvaluateWithError(trust, nil)
            }
        }

        /// Decodes each DER blob into a `SecCertificate`, or `nil` if any fails to parse.
        private static func certificates(_ ders: [[UInt8]]) -> [SecCertificate]? {
            var certificates: [SecCertificate] = []
            for der in ders {
                guard
                    let certificate = SecCertificateCreateWithData(nil, Data(der) as CFData)
                else {
                    return nil
                }
                certificates.append(certificate)
            }
            return certificates
        }
    }

#endif
