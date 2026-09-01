//
//  HTTP3StreamTable.swift
//  HTTP3
//
//  RFC 9114 §4.1 / RFC 9204 §2.1.2 — the per-connection stream table backing ``HTTP3Connection``. It is
//  a stream-id → state map that additionally maintains two running totals the engine would otherwise
//  recompute with an O(streams) reduce on a hot path:
//
//    • ``totalBufferedBody`` — buffered (un-dispatched) request-body octets summed across streams, the
//      connection-wide body budget checked on every DATA frame (CWE-400 / CWE-770);
//    • ``blockedSectionCount`` — streams parked on not-yet-received QPACK inserts, checked against
//      SETTINGS_QPACK_BLOCKED_STREAMS each time a section blocks (RFC 9204 §2.1.2).
//
//  Both checks are attacker-amplifiable to the concurrent-stream cap, so the counters make them O(1).
//  The backing storage is `private`: every mutation flows through the counter-maintaining subscript or
//  `removeValue(forKey:)`, so the counters cannot drift from the table's contents (the one hazard for
//  this DoS budget — see HTTP3BufferBudgetConsistencyTests).
//

internal import HTTPCore

/// A stream-id → ``HTTP3Connection/StreamState`` map with O(1) running buffered-body and blocked-section
/// totals.
struct HTTP3StreamTable: Sequence {
    private typealias Storage = [QUICStreamID: HTTP3Connection.StreamState]

    private var storage: Storage = [:]

    /// The sum of every tracked stream's buffered request-body byte count (`body.count`).
    ///
    /// Maintained on each mutation; equal to `reduce(0) { $0 + $1.value.body.count }` by construction
    /// (RFC 9114 §4.1).
    private(set) var totalBufferedBody = 0

    /// The number of tracked streams whose HEADERS section is blocked on not-yet-received inserts.
    ///
    /// Counts records with `blockedSection != nil`; maintained on each mutation (RFC 9204 §2.1.2).
    private(set) var blockedSectionCount = 0

    subscript(id: QUICStreamID) -> HTTP3Connection.StreamState? {
        get { storage[id] }
        set {
            // Resolve the prior state in the same mutation that installs the new one, so both deltas are
            // exact and the table is touched once on the DATA / HEADERS hot path.
            let previous: HTTP3Connection.StreamState?
            if let newValue {
                previous = storage.updateValue(newValue, forKey: id)
            }
            else {
                previous = storage.removeValue(forKey: id)
            }
            totalBufferedBody += (newValue?.body.count ?? 0) - (previous?.body.count ?? 0)
            blockedSectionCount += Self.blockedFlag(newValue) - Self.blockedFlag(previous)
        }
    }

    /// Removes and returns the state for `id`, debiting its buffered body and blocked-section flag.
    @discardableResult
    mutating func removeValue(forKey id: QUICStreamID) -> HTTP3Connection.StreamState? {
        let removed = storage.removeValue(forKey: id)
        totalBufferedBody -= removed?.body.count ?? 0
        blockedSectionCount -= Self.blockedFlag(removed)
        return removed
    }

    /// The number of tracked streams — the record count a driver is obliged to retire (audit REG-3).
    var count: Int { storage.count }

    /// Takes a stream's receive buffer out of the table, leaving its record in place.
    ///
    /// The record keeps an empty buffer, so nothing else observes a gap.
    ///
    /// The engine walks those octets through a borrowed `RawSpan` while mutating itself, which Swift's
    /// exclusivity rules forbid on state the table still holds — and any later `append` or `removeAll`
    /// on a buffer the table still shares would pay a copy-on-write copy of the whole thing. Handing
    /// the storage out with sole ownership solves both, and costs nothing: it is a pointer move
    /// (audit CR-F18).
    ///
    /// This reaches `storage` directly rather than going through the counter-maintaining subscript,
    /// which is sound *because* it changes neither `body` nor `blockedSection` — the two quantities
    /// the running totals track. Nothing else here may take that shortcut.
    mutating func takeBuffer(of id: QUICStreamID) -> (buffer: [UInt8], start: Int)? {
        guard var state = storage.removeValue(forKey: id) else {
            return nil
        }
        var taken: [UInt8] = []
        swap(&taken, &state.buffer)
        let start = state.bufferStart
        state.bufferStart = 0
        storage[id] = state
        return (taken, start)
    }

    /// Returns a taken buffer to `id` with the cursor at `consumed`, reclaiming any dead prefix.
    ///
    /// Does nothing when a handler retired the stream while its octets were borrowed — that stream is
    /// gone and its buffer goes with it.
    mutating func restoreBuffer(
        _ buffer: inout [UInt8],
        of id: QUICStreamID,
        consumedTo consumed: Int
    ) {
        guard var state = storage.removeValue(forKey: id) else {
            return
        }
        swap(&state.buffer, &buffer)
        state.bufferStart = consumed
        state.reclaimBuffer()
        storage[id] = state
    }

    func makeIterator() -> Dictionary<QUICStreamID, HTTP3Connection.StreamState>.Iterator {
        storage.makeIterator()
    }

    /// `1` when the state holds a blocked HEADERS section, else `0` (RFC 9204 §2.1.2).
    private static func blockedFlag(_ state: HTTP3Connection.StreamState?) -> Int {
        state?.blockedSection == nil ? 0 : 1
    }
}
