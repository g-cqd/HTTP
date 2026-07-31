//
//  HTTP3ConnectionCensus.swift
//  HTTP3
//
//  What one ``HTTP3Connection`` still retains, in the four quantities a peer can grow (audit REG-3).
//
//  The engine is sans-I/O: it learns a stream is gone only when the driver tells it. Every one of these
//  totals is therefore a driver obligation, and a driver that resets a stream on the wire without
//  retiring it here leaks all four at once — the parser buffer and decoded request, the buffered body
//  counted against the connection-wide budget (RFC 9114 §4.1), the stream's slot in the
//  SETTINGS_QPACK_BLOCKED_STREAMS allowance (RFC 9204 §2.1.2), and the abuse charge the reset was
//  supposed to cost the peer (RFC 9114 §8.1).
//
//  Surfaced as one value rather than four accessors so a caller reads a consistent snapshot: under the
//  driver's actor the four are only coherent if they are taken in a single call.
//

/// A snapshot of the per-connection state an ``HTTP3Connection`` still holds.
public struct HTTP3ConnectionCensus: Sendable, Equatable {
    /// The per-stream records the engine is tracking (RFC 9114 §6.1).
    public let trackedStreams: Int

    /// The streams whose HEADERS section is blocked on not-yet-received QPACK inserts.
    ///
    /// Bounded by SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 §2.1.2); a retained blocked stream consumes
    /// that allowance until the driver retires it.
    public let blockedSections: Int

    /// The buffered, un-dispatched request-body octets held across every tracked stream (RFC 9114 §4.1).
    public let bufferedRequestBodyBytes: Int

    /// Stream resets charged against the rolling abuse budget in the current window (RFC 9114 §8.1).
    ///
    /// Peer RESET_STREAM and engine- or driver-initiated resets alike, so neither Rapid Reset
    /// (CVE-2023-44487) nor MadeYouReset (CVE-2025-8671) can bypass the cap.
    public let chargedStreamResets: Int

    /// Creates a census snapshot.
    public init(
        trackedStreams: Int,
        blockedSections: Int,
        bufferedRequestBodyBytes: Int,
        chargedStreamResets: Int
    ) {
        self.trackedStreams = trackedStreams
        self.blockedSections = blockedSections
        self.bufferedRequestBodyBytes = bufferedRequestBodyBytes
        self.chargedStreamResets = chargedStreamResets
    }
}
