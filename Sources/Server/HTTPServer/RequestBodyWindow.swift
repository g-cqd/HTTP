//
//  RequestBodyWindow.swift
//  HTTPServer
//
//  The fixed receive window a *streamed* HTTP/1.1 chunked request body is framed inside (RFC 9112
//  §7.1). A chunked body declares no length, so its framing has to be decoded before its extent is
//  known — which is why the old streaming path let the whole encoded body accumulate in the
//  connection's keep-alive buffer. This bounds it instead: octets arrive into a window of a configured
//  size, the decoder consumes from it, and the decoded prefix is dropped before the next read, so the
//  live cost of an arbitrarily large upload is one window plus one chunk in flight.
//
//  The window never grows past its capacity, which is what makes the read a *bounded* read rather than
//  an accumulation — see ``HTTPLimits/effectiveRequestBodyWindow`` for why the configured size is
//  floored, and why that floor is what keeps a full window from deadlocking the decoder.
//

/// A fixed-capacity, self-compacting receive window for a streamed HTTP/1.1 request body.
///
/// Holds a decoded prefix (dropped on the next ``makeRoom()``) followed by the octets the decoder has
/// not framed yet. A value type: the producer threads one `inout` through its read loop, so the
/// storage grows in place and is never copied per read.
struct RequestBodyWindow {
    /// The window's octets — a decoded prefix of ``position`` octets, then the unframed remainder.
    ///
    /// Read directly by the decoder driver (`bytes.withUnsafeBytes`), so the framing pass borrows the
    /// storage rather than copying out of it.
    private(set) var bytes: [UInt8]

    /// How far into ``bytes`` the decoder has advanced.
    private(set) var position = 0

    /// The most octets ``bytes`` may hold — the hard bound on what one streaming connection retains
    /// on the wire side.
    let capacity: Int

    /// Creates a window of `capacity` octets already holding `seed`.
    ///
    /// `seed` is the body prefix that arrived alongside the request head: the reader's last receive
    /// overshoots the header section, and those octets have to be framed like any others. It may
    /// exceed `capacity` — the head read's overshoot is bounded by its own read size, not by this —
    /// in which case the window simply starts full and the first ``makeRoom()`` after the decoder
    /// consumes brings it back under.
    init(capacity: Int, seeding seed: ArraySlice<UInt8>) {
        self.capacity = capacity
        bytes = []
        bytes.reserveCapacity(max(capacity, seed.count))
        bytes.append(contentsOf: seed)
    }

    /// The octets received but not yet framed — what the decoder has left to work with.
    var unframedCount: Int { bytes.count - position }

    /// The octets after the framed body: a pipelined follow-up request, handed back to the connection
    /// buffer once the body completes so the keep-alive cursor stays exact.
    var remainder: ArraySlice<UInt8> { bytes[position...] }

    /// Drops the decoded prefix and returns how many octets may now be received.
    ///
    /// Called once before each read, so the shift is over the unframed remainder only — which the
    /// decoder has just drained to a partial framing line in the common case, making the compaction
    /// a few octets rather than a window-sized memmove. The result is strictly positive: see
    /// ``HTTPLimits/effectiveRequestBodyWindow``.
    mutating func makeRoom() -> Int {
        if position > 0 {
            bytes.removeFirst(position)  // Array keeps its storage — a shift, not a reallocation
            position = 0
        }
        return capacity - bytes.count
    }

    /// Adopts `chunk` as newly received octets.
    mutating func append(_ chunk: [UInt8]) {
        bytes.append(contentsOf: chunk)
    }

    /// Records that the decoder framed up to `position` octets of ``bytes``.
    mutating func advance(to position: Int) {
        self.position = position
    }
}
