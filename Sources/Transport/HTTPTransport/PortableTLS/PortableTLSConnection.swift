//
//  PortableTLSConnection.swift
//  HTTPTransport
//
//  A ``TransportConnection`` backed by a libssl `SSL` over an accepted socket (the portable, non-
//  Network.framework backbone — ADR 0004). The mirror of ``NetworkFrameworkConnection``.
//
//  Byte-bridge model (v1): `SSL_set_fd` on a *blocking* accepted socket, with every SSL operation
//  offloaded to a per-connection serial `DispatchQueue` and bridged to `async` via a continuation —
//  the connection's I/O never blocks a cooperative thread, and SSL access is serialized (so the `SSL`
//  is single-threaded, as libssl requires). This is the ADR's sanctioned first step; the
//  higher-throughput path (non-blocking fd + memory BIOs driven by a shared readiness loop, avoiding a
//  thread per in-flight op) is the noted follow-up. Teardown is once-only (guarded by `lifecycle`),
//  from `close()` or `deinit`.
//
//  Gated `#if canImport(CHTTPBoringSSL)` — present only in the opt-in portable build (`HTTP_PORTABLE_TLS`).
//

#if canImport(CHTTPBoringSSL)

    internal import CHTTPBoringSSL
    internal import Darwin
    internal import Dispatch
    internal import Synchronization

    /// A ``TransportConnection`` backed by a libssl `SSL` over a blocking accepted socket.
    ///
    /// All `SSL`/fd access is confined to ``queue`` (libssl `SSL` objects are not thread-safe), so the
    /// type is safe to share across tasks — `@unchecked Sendable`, like ``NetworkFrameworkConnection``.
    final class PortableTLSConnection: TransportConnection, @unchecked Sendable {
        let id: TransportConnectionID
        let peer: TransportAddress
        let isSecure = true

        /// The ALPN protocol captured at ``performHandshake()`` (RFC 7301), or `nil` before the handshake
        /// completes or when none was negotiated.
        var negotiatedApplicationProtocol: String? { negotiated.withLock(\.self) }

        private let ssl: OpaquePointer
        private let descriptor: Int32
        private let queue = DispatchQueue(label: "http.transport.portable-tls")
        private let negotiated = Mutex<String?>(nil)
        /// `true` once the `SSL` and socket have been torn down (once-only across ``close()`` / `deinit`).
        private let lifecycle = Mutex<Bool>(false)

        /// Wraps an `SSL` already bound to `descriptor` via `SSL_set_fd` (the caller owns that wiring); the
        /// connection takes ownership and tears both down on ``close()``.
        init(
            id: TransportConnectionID, peer: TransportAddress, ssl: OpaquePointer, descriptor: Int32
        ) {
            self.id = id
            self.peer = peer
            self.ssl = ssl
            self.descriptor = descriptor
        }

        deinit {
            // Best-effort if `close()` was never called; once-guarded so it can't double-free.
            teardown()
        }

        /// Drives the server-side TLS handshake (`SSL_accept`) to completion and captures the negotiated
        /// ALPN protocol, or throws if the handshake fails.
        func performHandshake() async throws {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                queue.async {
                    let result = SSL_accept(self.ssl)
                    guard result == 1 else {
                        let message = "SSL_accept failed (error \(SSL_get_error(self.ssl, result)))"
                        continuation.resume(
                            throwing: TransportError.tlsConfigurationFailed(message)
                        )
                        return
                    }
                    self.negotiated.withLock {
                        $0 = OpenSSLTLS.negotiatedApplicationProtocol(of: self.ssl)
                    }
                    continuation.resume()
                }
            }
        }

        /// Receives up to `maxLength` decrypted bytes, or `nil` once the peer closes (TLS close-notify).
        func receive(maxLength: Int) async throws -> [UInt8]? {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<[UInt8]?, any Error>) in
                queue.async {
                    if self.lifecycle.withLock(\.self) {
                        continuation.resume(returning: nil)
                        return
                    }
                    var buffer = [UInt8](repeating: 0, count: max(1, maxLength))
                    let count = buffer.withUnsafeMutableBytes { raw in
                        SSL_read(self.ssl, raw.baseAddress, Int32(raw.count))
                    }
                    if count > 0 {
                        buffer.removeLast(buffer.count - Int(count))
                        continuation.resume(returning: buffer)
                        return
                    }
                    let status = SSL_get_error(self.ssl, count)
                    // A clean close-notify (`ZERO_RETURN`) or an abrupt peer EOF (`SYSCALL` with no error
                    // queued) is end-of-stream — surfaced as `nil`, matching the other backbones.
                    if status == SSL_ERROR_ZERO_RETURN || status == SSL_ERROR_SYSCALL {
                        continuation.resume(returning: nil)
                    }
                    else {
                        continuation.resume(
                            throwing: TransportError.ioFailed("SSL_read error \(status)")
                        )
                    }
                }
            }
        }

        /// Sends `bytes` to the peer, encrypting and writing them in full.
        func send(_ bytes: [UInt8]) async throws {
            if bytes.isEmpty {
                return
            }
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                queue.async {
                    if self.lifecycle.withLock(\.self) {
                        continuation.resume(throwing: TransportError.closed)
                        return
                    }
                    let count = bytes.withUnsafeBytes { raw in
                        SSL_write(self.ssl, raw.baseAddress, Int32(raw.count))
                    }
                    guard count > 0 else {
                        let message = "SSL_write error \(SSL_get_error(self.ssl, count))"
                        continuation.resume(throwing: TransportError.ioFailed(message))
                        return
                    }
                    continuation.resume()
                }
            }
        }

        /// Closes the connection: TLS close-notify, then frees the `SSL` and the socket.
        func close() async {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                queue.async {
                    self.teardown()
                    continuation.resume()
                }
            }
        }

        /// Frees the `SSL` and closes the socket exactly once (idempotent across ``close()`` / `deinit`).
        private func teardown() {
            let firstTeardown = lifecycle.withLock { closed -> Bool in
                defer { closed = true }
                return !closed
            }
            guard firstTeardown else {
                return
            }
            SSL_shutdown(ssl)
            SSL_free(ssl)
            _ = Darwin.close(descriptor)
        }
    }

#endif
