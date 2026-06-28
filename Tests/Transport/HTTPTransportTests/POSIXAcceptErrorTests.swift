//
//  POSIXAcceptErrorTests.swift
//  HTTPTransportTests
//
//  accept() failure classification for the BSD-socket backbones (audit F-EMFILE). The shared
//  `POSIXSocket.classifyAcceptError` must be a pure mapping that never sleeps: file-descriptor
//  exhaustion (EMFILE/ENFILE) classifies as `.backoff` so each accept loop can delay *off* its
//  I/O-bearing queue, rather than the old inline `usleep` that stalled the kqueue event loop (and
//  with it every live connection's I/O) on the way to a retry.
//

import Testing

@testable import HTTPTransport

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#endif

@Suite("POSIXSocket accept-error classification (audit F-EMFILE)")
struct POSIXAcceptErrorTests {
    @Test("each accept() errno maps to the action its loop takes — and the helper never sleeps")
    func classifyAcceptError() {
        // No connection pending — a non-blocking listener is drained.
        #expect(POSIXSocket.classifyAcceptError(EAGAIN) == .wouldBlock)
        #expect(POSIXSocket.classifyAcceptError(EWOULDBLOCK) == .wouldBlock)
        // Transient — retry immediately.
        #expect(POSIXSocket.classifyAcceptError(EINTR) == .retry)
        #expect(POSIXSocket.classifyAcceptError(ECONNABORTED) == .retry)
        // fd exhaustion must classify as .backoff so the caller delays off its I/O-bearing queue; the
        // helper itself must not block (the old inline usleep stalled the kqueue loop — audit F-EMFILE).
        #expect(POSIXSocket.classifyAcceptError(EMFILE) == .backoff)
        #expect(POSIXSocket.classifyAcceptError(ENFILE) == .backoff)
        // The listener is gone or unrecoverable — stop accepting.
        #expect(POSIXSocket.classifyAcceptError(EBADF) == .stop)
        #expect(POSIXSocket.classifyAcceptError(EINVAL) == .stop)
    }
}
