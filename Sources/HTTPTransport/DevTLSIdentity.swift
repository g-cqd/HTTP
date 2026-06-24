//
//  DevTLSIdentity.swift
//  HTTPTransport
//
//  A DEVELOPMENT / TESTING convenience that mints an ephemeral self-signed PKCS#12 (RFC 7292)
//  identity by shelling out to `openssl`, so the example server and acceptance tests can exercise
//  the TLS + ALPN (h2) path without a real certificate. PRODUCTION callers MUST NOT use this — they
//  supply their own identity through ``TransportTLS`` (a CA-issued or organisation PKCS#12).
//
//  Apple's Security framework offers no public API to *create* a self-signed certificate, so a tiny
//  `openssl` invocation is the pragmatic dev path; the resulting blob is fed through the same
//  ``TransportTLS`` → `SecPKCS12Import` route as a real identity (no special-casing downstream).
//

internal import Foundation

/// Mints throwaway self-signed TLS identities for local development and tests (never for production).
public enum DevTLSIdentity {
    /// A self-signed identity for `commonName`, advertising `applicationProtocols` over ALPN.
    ///
    /// Generates a fresh 2048-bit RSA key and a 1-year self-signed certificate (CN + `localhost` /
    /// `127.0.0.1` SANs), exports them to a password-protected PKCS#12, and returns it as a
    /// ``TransportTLS``. Throws ``TransportError/tlsConfigurationFailed(_:)`` if `openssl` is absent
    /// or fails.
    public static func selfSigned(
        commonName: String = "localhost",
        passphrase: String = "http-dev",
        applicationProtocols: [String] = ["h2", "http/1.1"]
    ) throws -> TransportTLS {
        let pkcs12 = try makePKCS12(commonName: commonName, passphrase: passphrase)
        return TransportTLS(
            pkcs12: [UInt8](pkcs12),
            passphrase: passphrase,
            applicationProtocols: applicationProtocols
        )
    }

    private static func makePKCS12(commonName: String, passphrase: String) throws -> Data {
        let manager = FileManager.default
        let directory = manager.temporaryDirectory.appendingPathComponent(
            "http-dev-tls-\(UUID().uuidString)",
            isDirectory: true
        )
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: directory) }

        let key = directory.appendingPathComponent("key.pem").path
        let certificate = directory.appendingPathComponent("cert.pem").path
        let bundle = directory.appendingPathComponent("identity.p12").path

        try run([
            "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-keyout", key, "-out", certificate, "-days", "365",
            "-subj", "/CN=\(commonName)",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"
        ])
        // OpenSSL 3 defaults to AES-256 PKCS#12, which older `SecPKCS12Import` rejects; `-legacy`
        // restores the SHA1/3DES form it reads. LibreSSL (no `-legacy` flag) already emits that form.
        var export = [
            "pkcs12", "-export", "-inkey", key, "-in", certificate, "-out", bundle,
            "-name", commonName, "-passout", "pass:\(passphrase)"
        ]
        if try isOpenSSL3OrNewer() { export.insert("-legacy", at: 2) }
        try run(export)

        guard let data = manager.contents(atPath: bundle) else {
            throw TransportError.tlsConfigurationFailed("openssl produced no PKCS#12 output")
        }
        return data
    }

    /// Whether the resolved `openssl` is OpenSSL 3+ (which needs `-legacy`) rather than LibreSSL.
    private static func isOpenSSL3OrNewer() throws -> Bool {
        let version = try capture(["version"])
        return version.contains("OpenSSL 3") || version.contains("OpenSSL 4")
    }

    /// Runs `openssl` with `arguments`, throwing with stderr on a non-zero exit.
    private static func run(_ arguments: [String]) throws {
        _ = try invoke(arguments, captureOutput: false)
    }

    /// Runs `openssl version` (etc.) and returns its standard output.
    private static func capture(_ arguments: [String]) throws -> String {
        try invoke(arguments, captureOutput: true)
    }

    private static func invoke(_ arguments: [String], captureOutput _: Bool) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["openssl"] + arguments
        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors
        do {
            try process.run()
        }
        catch {
            throw TransportError.tlsConfigurationFailed("could not launch openssl: \(error)")
        }
        // Drain before waiting so a large write cannot deadlock against a full pipe buffer.
        let stdout = output.fileHandleForReading.readDataToEndOfFile()
        let stderr = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw TransportError.tlsConfigurationFailed(
                "openssl \(arguments.first ?? "") failed: "
                    + String(decoding: stderr, as: Unicode.UTF8.self)
            )
        }
        return String(decoding: stdout, as: Unicode.UTF8.self)
    }
}
