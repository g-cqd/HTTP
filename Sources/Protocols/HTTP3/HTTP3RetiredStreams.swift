//
//  HTTP3RetiredStreams.swift
//  HTTP3
//
//  Which request streams one connection has finished with, in bounded memory (audit R5-P0c).
//
//  The engine materializes a stream record lazily, from whatever octets it is handed, so retirement was
//  a suggestion: a stream that had been reset or answered came straight back the moment the next queued
//  chunk for it arrived, with a fresh parser buffer, a fresh share of the RFC 9114 §4.1 buffered-body
//  budget and a fresh claim on the SETTINGS_QPACK_BLOCKED_STREAMS allowance (RFC 9204 §2.1.2). This is
//  what makes retirement terminal instead.
//
//  A plain "highest retired id" watermark is the obvious O(1) answer and it is **wrong**. Streams do not
//  retire in id order: a connection can serve stream 8 to completion while stream 0 has QUIC-opened but
//  not yet sent its HEADERS, and a bare watermark then refuses stream 0's first octets and drops a
//  perfectly good request. (Found by the R5-P0b racing test, which delivers two requests concurrently
//  and lost one.) RFC 9000 §2.1 says an out-of-order id implicitly opens the lower ones — but "opened"
//  is not "has already spoken", and the engine only has records for streams that have.
//
//  So: a *run* of retired ids that starts at id 0 and grows one stride at a time, plus the out-of-order
//  remainder held apart until the run reaches it. In the ordinary in-order case the remainder is empty
//  or holds one id and every operation is O(1). It fills only while some lower id is still live, and it
//  is capped: past ``capacity`` the run gives up on the missing id and starts anyway, after which it
//  closes over the remainder instead of accumulating it.
//
//  Giving up is the one over-approximation, and it is bounded in *when* as well as in size. It takes
//  ``capacity`` retirements that the missing stream never joined — by which point a stream that has
//  sent nothing has long since been reset by its own header read deadline (RFC 9112 §9.3 applied to
//  §4.1), which retires it and lets the run advance honestly. The backstop exists for a peer that goes
//  out of its way to leave gaps, not for the ordinary path.
//
//  Standards: RFC 9000 §2.1 (stream id classes), §3.2 (a reset stream's inbound data is discarded);
//  RFC 9114 §4.1; RFC 9204 §2.1.2; CWE-770.
//

internal import HTTPCore

/// The request streams a connection has retired, as a contiguous watermark plus a bounded remainder.
struct HTTP3RetiredStreams {
    /// The stride between consecutive client-initiated bidirectional ids (RFC 9000 §2.1).
    private static let stride: UInt64 = 4

    /// The out-of-order remainder's ceiling, past which its lower half folds into the watermark.
    ///
    /// Comfortably above any sane concurrent-stream limit, so the fold is a backstop against a peer
    /// that deliberately leaves gaps rather than something the ordinary path ever reaches (CWE-770).
    static let capacity = 256

    /// Every request-stream id at or below this has been retired.
    private(set) var watermark: QUICStreamID?

    /// Retired ids *above* the watermark — the out-of-order remainder.
    private var above: Set<QUICStreamID> = []

    /// Records that `id` has been retired, absorbing it into the watermark when it extends the run.
    ///
    /// The run starts at id 0 and only ever grows by one stride at a time. Seeding it with whichever
    /// stream happened to retire *first* is the trap: a connection that answers stream 4 before
    /// stream 0 has said anything would set the watermark to 4 and then refuse stream 0's HEADERS —
    /// silently dropping a live request. Everything out of order waits in ``above`` until the run
    /// reaches it.
    mutating func retire(_ id: QUICStreamID) {
        guard id.kind == .clientBidirectional, !contains(id) else {
            return  // only request streams retire, and only once
        }
        above.insert(id)
        absorbContiguous()
        if above.count > Self.capacity {
            fold()
        }
    }

    /// Whether `id` names a request stream this connection has already retired.
    func contains(_ id: QUICStreamID) -> Bool {
        guard id.kind == .clientBidirectional else {
            return false
        }
        guard let watermark else {
            return above.contains(id)
        }
        return id <= watermark || above.contains(id)
    }

    /// Walks the remainder forward while it continues the run of retired ids, which begins at id 0.
    private mutating func absorbContiguous() {
        while true {
            let next = watermark.map { QUICStreamID($0.rawValue + Self.stride) } ?? QUICStreamID(0)
            guard above.remove(next) != nil else {
                return
            }
            watermark = next
        }
    }

    /// Folds the lower half of an over-full remainder into the watermark.
    ///
    /// Amortized O(log n) per retirement: the sort happens once per `capacity / 2` insertions. The
    /// alternative — evicting one id at a time — is an O(n) minimum search on a peer-driven path.
    private mutating func fold() {
        let ordered = above.sorted()
        let cut = ordered.count / 2
        guard cut > 0, let raised = ordered[cut - 1] as QUICStreamID? else {
            return
        }
        watermark = Swift.max(watermark ?? raised, raised)
        above = Set(ordered[cut...])
        absorbContiguous()
    }
}
