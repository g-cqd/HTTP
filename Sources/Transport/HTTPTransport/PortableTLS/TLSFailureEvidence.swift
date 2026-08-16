//
//  TLSFailureEvidence.swift
//  HTTPTransport
//
//  What a classified `SSL_*` call knew at the instant `SSL_get_error` said the failure was fatal —
//  captured THEN, because the evidence does not keep. BoringSSL's error queue is per-thread state:
//  `err.h` — "ERR_get_error gets the packed error code for the least recent error and removes that
//  error from the queue", and the vendored library clears the whole queue again on entry to every
//  classified call (`ssl_reset_error_state`, `ssl_lib.cc:79`). Whatever the queue held at an
//  `SSL_ERROR_SSL` exists exactly once, at the classification seam, and is gone by the next call.
//
//  This type exists because of a failure this project observed once and could not explain: a healthy
//  session's `SSL_read error 1` carrying `PEER_DID_NOT_RETURN_A_CERTIFICATE` — an entry belonging to
//  a different connection — roughly one run in twelve, never reproduced. The presumed mechanism (a
//  stale pre-call queue) was disproven by `PortableTLSErrorQueueTests`; the cause remains open. So a
//  fatal classification now carries the record that report lacked: every queue entry verbatim, the
//  connection the engine belongs to, the thread whose queue was drained, and which call failed. It
//  records; it claims nothing about why.
//
//  Reached only from ``PortableTLSEngine/classify(_:in:)``'s fatal arm — after `SSL_get_error` has
//  already ruled out every retryable outcome — so the ordinary read/write/handshake path never
//  allocates here, drains nothing, and pays nothing.
//
//  Standards: BoringSSL `include/openssl/err.h` — `ERR_get_error` (drains, least recent first) and
//  `ERR_error_string_n` ("generates a human-readable string", always NUL-terminated, into a caller
//  buffer of at least 120 bytes). Gated `#if canImport(CHTTPBoringSSLShims)` with the backbone.
//

#if canImport(CHTTPBoringSSLShims)

    internal import CHTTPBoringSSL
    #if canImport(Darwin)
        internal import Darwin
    #elseif canImport(Glibc)
        internal import Glibc
    #endif

    /// The evidence drained at the moment a classified `SSL_*` call came back fatal — see the file
    /// header for why it must be taken at that moment and not later.
    struct TLSFailureEvidence: Sendable, CustomStringConvertible {
        /// The most queue entries one capture drains.
        ///
        /// Eight is well past any observed depth (the field report carried one); a deeper queue is
        /// truncated rather than looped over unbounded.
        static let queueEntryCeiling = 8

        /// The `SSL_get_error` status the classification saw (`SSL_ERROR_SSL` is `1`).
        let status: Int32
        /// The classified entry point that failed: `SSL_accept`, `SSL_read`, or `SSL_write`.
        let call: StaticString
        /// The connection the engine was constructed for — the identity the field report lacked.
        let connectionID: TransportConnectionID
        /// The thread whose queue was drained; the queue is per-THREAD (`err.h`), so two failures
        /// with different thread values could not have shared one queue.
        let thread: UInt64
        /// Every entry `ERR_get_error` returned at capture, least recent first, each rendered by
        /// `ERR_error_string_n` (`error:{code}:{library}:OPENSSL_internal:{reason}`).
        let queueEntries: [String]

        /// Drains and renders the calling thread's error queue into a value that can outlive it.
        ///
        /// Called on the fatal classification path only, on the thread — and inside the engine
        /// acquisition — of the `SSL_*` call it describes, which is what ties the drained entries to
        /// that call and no other.
        static func capture(
            status: Int32,
            call: StaticString,
            connectionID: TransportConnectionID
        ) -> Self {
            var entries: [String] = []
            entries.reserveCapacity(queueEntryCeiling)
            while entries.count < queueEntryCeiling {
                let code = CHTTPBoringSSL_ERR_get_error()
                guard code != 0 else {
                    break
                }
                entries.append(render(code))
            }
            return Self(
                status: status,
                call: call,
                connectionID: connectionID,
                thread: currentThreadID(),
                queueEntries: entries
            )
        }

        /// Opens with the exact string the original field report captured (`SSL_read error 1`), so
        /// existing greps still match, then appends what that report was missing.
        var description: String {
            let queue = queueEntries.joined(separator: "; ")
            return "\(call) error \(status) "
                + "[connection \(connectionID.rawValue) thread \(thread) queue [\(queue)]]"
        }

        /// One packed error as `ERR_error_string_n` spells it.
        private static func render(_ code: UInt32) -> String {
            // 256 comfortably exceeds the 120 octets `err.h` documents as always sufficient.
            var buffer = [CChar](repeating: 0, count: 256)
            buffer.withUnsafeMutableBufferPointer { raw in
                guard let base = raw.baseAddress else {
                    return
                }
                // SE-0458 (ADR 0009): unsafe by the pointer parameter. The function writes at most
                // `raw.count` octets including the NUL it guarantees, and nothing escapes.
                _ = unsafe CHTTPBoringSSL_ERR_error_string_n(code, base, raw.count)
            }
            let octets = buffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:))
            // `err.h` promises ASCII, but a rendering is evidence, not data — never trap over it.
            return String(validating: octets, as: UTF8.self) ?? "unrenderable error \(code)"
        }

        /// The calling thread's identity — the cheapest stable value each platform offers, and only
        /// ever computed on the fatal path.
        private static func currentThreadID() -> UInt64 {
            #if canImport(Darwin)
                return UInt64(pthread_mach_thread_np(pthread_self()))
            #else
                return UInt64(pthread_self())
            #endif
        }
    }

#endif
