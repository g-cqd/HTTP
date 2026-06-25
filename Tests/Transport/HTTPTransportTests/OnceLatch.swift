//
//  OnceLatch.swift
//  HTTPTransportTests
//
//  Loopback acceptance for the legacy QUIC backbone (the plan's top risk): a real Network.framework
//  QUIC client over the dev cert exercises ``LegacyQUICTransport`` end-to-end through the ``QUIC*``
//  abstraction — accept a connection, take its inbound stream, read the bytes with QUIC's FIN
//  (RFC 9000 §2), and echo them back. This validates the `NWConnectionGroup` accept model and the
//  FIN→`isComplete` mapping the HTTP/3 server relies on. (`curl --http3` is unavailable — the
//  SecureTransport curl ships no QUIC library — so a Network.framework client is the acceptance.)
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
