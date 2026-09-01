//
//  InteropClient.swift
//  HTTPTransportTests
//
//  The interactive child-process driver of the interop matrix (`s_client` under a PTY):
//  write lines in, await substrings out, one accumulated transcript. See `InteropTools`
//  for why the PTY exists.
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

    /// An interactive child process (the `s_client` driver): write lines in, await
    /// substrings out, one accumulated transcript.
    final class InteropClient: @unchecked Sendable {
        private let process = Process()
        private let input = Pipe()
        private let collected = Mutex<String>("")

        init(_ executable: String, _ arguments: [String]) throws {
            // Under a PTY (via `script`), because `s_client` writes RECEIVED application
            // data to stdout, which libc block-buffers on a pipe — the echoed octets would
            // sit in the child's buffer forever. A PTY makes it line-buffered. The PTY also
            // locally echoes what WE type, which is why the echo scenarios await a
            // server-prefixed spelling rather than the raw probe.
            #if canImport(Darwin)
                process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
                process.arguments = ["-q", "/dev/null", executable] + arguments
            #else
                process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
                process.arguments = [
                    "-qefc", ([executable] + arguments).joined(separator: " "), "/dev/null"
                ]
            #endif
            let output = Pipe()
            process.standardOutput = output
            process.standardError = output
            process.standardInput = input
            // `Mutex` is ~Copyable, so the handler reaches it through `self` (weakly — the
            // handler is cleared in `terminate()`, and a torn-down client drops the bytes).
            output.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                guard !data.isEmpty, let self else {
                    return
                }
                let text = String(decoding: data, as: Unicode.UTF8.self)
                collected.withLock { $0 += text }
            }
            try process.run()
        }

        deinit {
            // `terminate()` is the tests' teardown; a leaked child dies with the runner.
        }

        /// Writes `text` to the child's stdin.
        func send(_ text: String) {
            input.fileHandleForWriting.write(Data(text.utf8))
        }

        /// Polls the transcript for `needle` until it appears or `seconds` elapse.
        func awaitOutput(containing needle: String, seconds: Int) -> Bool {
            let deadline = Date().addingTimeInterval(TimeInterval(seconds))
            while Date() < deadline {
                if collected.withLock({ $0.contains(needle) }) {
                    return true
                }
                usleep(50_000)
            }
            return false
        }

        /// Everything the child has said so far, both streams interleaved.
        func transcript() -> String {
            collected.withLock(\.self)
        }

        /// Closes stdin and terminates the child.
        func terminate() {
            try? input.fileHandleForWriting.close()
            if process.isRunning {
                process.terminate()
            }
        }
    }

#endif
