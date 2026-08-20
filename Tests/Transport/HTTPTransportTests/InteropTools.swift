//
//  InteropTools.swift
//  HTTPTransportTests
//
//  The harness under `HTTPTLSInteropTests`: system-tool discovery (which curl, which
//  openssl, and WHICH openssl — LibreSSL lacks the OpenSSL 3 behaviors two scenarios pin),
//  a one-shot process runner and an interactive `s_client` driver (stdin writes, deadline
//  reads), and the transport-level echo server every scenario dials. Kept apart from the
//  scenarios so the matrix file reads as the matrix.
//

#if canImport(CHTTPBoringSSLShims) || HTTP_PORTABLE_TLS_SWIFT

    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif
    internal import Foundation
    internal import Synchronization

    @testable import HTTPTransport

    /// System-tool discovery and process driving for the interop matrix.
    enum InteropTools {
        /// The first executable named `tool` on the common paths, or nil.
        static func which(_ tool: String) -> String? {
            let candidates = [
                "/usr/bin/\(tool)", "/opt/homebrew/bin/\(tool)",
                "/opt/homebrew/opt/openssl/bin/\(tool)", "/usr/local/bin/\(tool)",
                "/usr/local/opt/openssl/bin/\(tool)", "/bin/\(tool)"
            ]
            return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
        }

        /// A TLS 1.3-capable curl, or nil.
        ///
        /// macOS's `/usr/bin/curl` defaults to the SecureTransport backend, which parses
        /// `--tlsv1.3` but refuses it AT HANDSHAKE TIME (exit 4, silently under `-s`) —
        /// measured on curl 8.7.1. A curl is admitted here only when its version line names
        /// a TLS 1.3-capable backend; Linux distribution curls are OpenSSL-backed and pass.
        static let curl: String? = {
            let backends = ["OpenSSL", "BoringSSL", "GnuTLS", "wolfSSL", "rustls", "quictls"]
            for candidate in [
                "/opt/homebrew/opt/curl/bin/curl", "/opt/homebrew/bin/curl",
                "/usr/local/opt/curl/bin/curl", "/usr/local/bin/curl", "/usr/bin/curl",
                "/bin/curl"
            ] where FileManager.default.isExecutableFile(atPath: candidate) {
                if let version = try? run(candidate, ["--version"], timeout: 10),
                    backends.contains(where: version.contains)
                {
                    return candidate
                }
            }
            return nil
        }()

        /// ANY openssl-compatible s_client (OpenSSL or LibreSSL), or nil.
        static let openssl: String? = which("openssl")

        /// An OpenSSL 3+ specifically — the ticket banner and `-msg` KeyUpdate scenarios
        /// pin its output; LibreSSL spells both differently (or not at all).
        static let opensslThree: String? = {
            for candidate in [
                "/opt/homebrew/opt/openssl/bin/openssl", "/opt/homebrew/bin/openssl",
                "/usr/local/opt/openssl/bin/openssl", "/usr/bin/openssl", "/bin/openssl"
            ] where FileManager.default.isExecutableFile(atPath: candidate) {
                if let version = try? run(candidate, ["version"], timeout: 10),
                    version.contains("OpenSSL 3") || version.contains("OpenSSL 4")
                {
                    return candidate
                }
            }
            return nil
        }()

        /// Runs `executable` to completion (with optional stdin), returning stdout+stderr.
        ///
        /// `s_client` keeps the session open until stdin closes, so one-shot scenarios pass
        /// `stdin: ""` to hand it an immediately-closed pipe.
        static func run(
            _ executable: String,
            _ arguments: [String],
            stdin: String? = nil,
            timeout: Int
        ) throws -> String {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            let output = Pipe()
            process.standardOutput = output
            process.standardError = output  // s_client narrates on stderr — one transcript
            if let stdin {
                let input = Pipe()
                process.standardInput = input
                try process.run()
                input.fileHandleForWriting.write(Data(stdin.utf8))
                try? input.fileHandleForWriting.close()
            }
            else {
                try process.run()
            }
            let watchdog = DispatchWorkItem { process.terminate() }
            DispatchQueue.global()
                .asyncAfter(deadline: .now() + .seconds(timeout), execute: watchdog)
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            watchdog.cancel()
            return String(decoding: data, as: Unicode.UTF8.self)
        }

        /// One recorded matrix line: client, exact command, verdict (and the detail on
        /// failure, so a red run carries its own evidence).
        static func record(
            _ client: String, _ arguments: [String], pass: Bool, detail: String
        ) {
            let command = ([client] + arguments).joined(separator: " ")
            print("INTEROP: [\(pass ? "PASS" : "FAIL")] \(command)")
            if !pass {
                print("INTEROP-DETAIL: \(detail.suffix(2_000))")
            }
        }

        /// The `subject=` line of an `s_client` transcript (OpenSSL and LibreSSL spellings).
        static func subjectLine(of output: String) -> String {
            output.components(separatedBy: "\n").first { $0.contains("subject=") } ?? ""
        }
    }

#endif
