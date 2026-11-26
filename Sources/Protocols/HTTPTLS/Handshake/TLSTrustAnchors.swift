//
//  TLSTrustAnchors.swift
//  HTTPTLS
//
//  A parsed, shareable RFC 5280 §6.1 trust-anchor set: decoded once (from DER roots or an RFC 7468
//  PEM bundle such as the platform's `ca-certificates`), then shared by every chain validator that
//  pins it — so a client opening many connections never re-decodes ~150 roots per handshake.
//

// swiftlint:disable sorted_imports - swift-format's OrderedImports places declaration imports last
internal import SwiftASN1
internal import X509
internal import struct Foundation.Data
internal import class Foundation.FileManager

// swiftlint:enable sorted_imports

/// A decoded set of trust anchors (RFC 5280 §6.1), shared across chain validations.
public struct TLSTrustAnchors: Sendable {
    /// The well-known locations of the platform PEM root bundle (macOS, Debian/Ubuntu, Fedora/RHEL,
    /// Alpine/OpenSUSE), probed in order by ``systemBundle(paths:)``.
    public static let systemBundlePaths = [
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem"
    ]

    /// The decoded anchors.
    let store: CertificateStore
    /// How many anchors were decoded.
    public let count: Int

    /// Decodes `rootsDER` (each one DER certificate); throws on an empty or undecodable set.
    public init(rootsDER: [[UInt8]]) throws(TLSX509ChainValidator.ConfigurationError) {
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
        store = CertificateStore(anchors)
        count = anchors.count
    }

    /// Decodes every `CERTIFICATE` block of an RFC 7468 PEM bundle, skipping undecodable entries
    /// (platform bundles carry the odd legacy root); throws when none decode.
    public init(pemBundle: String) throws(TLSX509ChainValidator.ConfigurationError) {
        let documents = (try? PEMDocument.parseMultiple(pemString: pemBundle)) ?? []
        var anchors: [Certificate] = []
        anchors.reserveCapacity(documents.count)
        for document in documents where document.discriminator == "CERTIFICATE" {
            if let certificate = try? Certificate(derEncoded: Array(document.derBytes)) {
                anchors.append(certificate)
            }
        }
        guard !anchors.isEmpty else {
            throw .noTrustRoots
        }
        store = CertificateStore(anchors)
        count = anchors.count
    }

    /// Loads the first readable platform PEM bundle among `paths`, or `nil` when none is present.
    public static func systemBundle(paths: [String] = systemBundlePaths) -> Self? {
        for path in paths {
            guard let data = FileManager.default.contents(atPath: path),
                let text = String(validating: Array(data), as: UTF8.self),
                let anchors = try? Self(pemBundle: text)
            else { continue }
            return anchors
        }
        return nil
    }
}
