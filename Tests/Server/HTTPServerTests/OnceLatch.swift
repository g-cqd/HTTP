//
//  OnceLatch.swift
//  HTTPServerTests
//
//  The M7 end-to-end acceptance: a real Network.framework QUIC client performs an HTTP/3 (RFC 9114)
//  GET over the legacy QUIC transport against the live server, and gets the responder's reply back —
//  exercising the whole stack (LegacyQUICTransport → serveHTTP3 → HTTP3Connection → QPACK → responder
//  → response framing) over loopback. (`curl --http3` is unavailable, so a Network.framework client is
//  the acceptance.)
//

import Foundation

/// A thread-safe "resume exactly once" latch for bridging callback state to a continuation.
final class OnceLatch: @unchecked Sendable {
    private let lock = NSLock()
    private var taken = false

    func take() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if taken {
            return false
        }
        taken = true
        return true
    }

    deinit {
        // No teardown beyond ARC.
    }
}
