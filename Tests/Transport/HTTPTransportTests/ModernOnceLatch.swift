//
//  ModernOnceLatch.swift
//  HTTPTransportTests
//
//  Loopback acceptance for the modern (macOS 26+) QUIC backbone, selected through
//  ``QUICTransportFactory`` on this OS: a real Network.framework QUIC client over the dev cert
//  exercises the typed-channel `NetworkConnection<QUIC>` transport end-to-end through the ``QUIC*``
//  abstraction — accept a connection, take its inbound stream, read the bytes with QUIC's FIN
//  (RFC 9000 §2), and echo them back. Skipped below macOS 26 (where the factory picks the legacy
//  backbone, covered by LegacyQUICTransportTests).
//

import Foundation

/// A thread-safe "resume exactly once" latch for bridging callback state to a continuation.
final class ModernOnceLatch: @unchecked Sendable {
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
