//
//  HTTPServer+HTTP2Reader.swift
//  HTTPServer
//
//  The HTTP/2 reader task: owns `connection.receive` for the connection's whole life, decoupled from
//  every handler, relay, and tunnel pump, so the next inbound read is never gated behind application
//  work. Never touches the engine — only the merged-mailbox consumer does.
//
//  It feeds a lossless ``BoundedByteChannel`` and yields one payload-free ticket per item (2026-07-31
//  audit, finding 3). Previously it yielded the octets themselves into an `.unbounded` mailbox in an
//  unconditional `while true`, while its sole consumer also did protocol *and* application-adjacent
//  work — so an adversarial peer, especially one sending invalid or flow-control-exempt traffic, could
//  outpace that consumer and grow server memory without limit. Now the reader parks at the channel's
//  byte watermark, stops calling `receive`, and the kernel receive buffer fills until the peer's TCP
//  window closes. Nothing is dropped: a drop policy is never valid for transport octets.
//

internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Reads octets into `intake`, yielding one `.inboundReady` ticket per queued item.
    ///
    /// Times its receives against `deadline` — the same parameter ``serveHTTP2(_:deadline:initialBytes:)``
    /// is passed, so read-side Slowloris protection (RFC 9112 §9.3) is unchanged. It also arms that
    /// deadline around the handoff itself: while parked waiting for the consumer to drain there is no
    /// receive outstanding, so without it a permanently wedged consumer would leave the watchdog napping
    /// forever and hold the connection open. A merely slow consumer re-arms per chunk and is not reaped.
    func runHTTP2Reader(
        _ connection: any TransportConnection,
        deadline: IdleDeadline<C.Instant>,
        initialBytes: [UInt8],
        into intake: BoundedByteChannel,
        signalling continuation: AsyncStream<HTTP2Wakeup>.Continuation
    ) async {
        if !initialBytes.isEmpty, await intake.send(initialBytes) == .queued {
            continuation.yield(.inboundReady)
        }
        while !Task.isCancelled {
            deadline.arm(clock.now.advanced(by: limits.idleTimeout))
            let chunk = try? await connection.receive(maxLength: 16_384)
            deadline.disarm()
            guard let chunk, !chunk.isEmpty else {
                break  // EOF, idle timeout, or read failure
            }
            deadline.arm(clock.now.advanced(by: limits.idleTimeout))
            let acceptance = await intake.send(chunk)
            deadline.disarm()
            // Exactly one ticket per dequeueable item. A coalesced send produced no new item, so
            // ticketing it would park the sole consumer on an item that does not exist.
            if acceptance == .queued {
                continuation.yield(.inboundReady)
            }
        }
        await intake.finish()
        continuation.yield(.inboundReady)  // the ticket that delivers the terminal item
    }
}
