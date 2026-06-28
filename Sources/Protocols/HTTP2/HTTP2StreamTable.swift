//
//  HTTP2StreamTable.swift
//  HTTP2
//
//  RFC 9113 §6.9 — the per-connection stream table backing ``HTTP2Connection``. It is a stream-id →
//  record map that additionally maintains a running ``totalBufferedBody``: the sum, across every
//  tracked stream, of buffered (un-dispatched) request-body octets. The connection-wide body budget
//  (CWE-400 / CWE-770) checks that sum on *every* DATA frame; recomputing it with an O(streams) reduce
//  would let a peer that opens the full concurrent-stream cap amplify each DATA frame's cost. The
//  counter makes the check O(1).
//
//  The backing storage is `private`, so every mutation flows through the counter-maintaining subscript
//  or `removeValue(forKey:)` — the counter cannot drift out of step with the table's contents, the one
//  hazard called out for this DoS budget (see HTTP2BufferBudgetConsistencyTests).
//

/// A stream-id → ``HTTP2Connection/StreamRecord`` map with an O(1) running buffered-body total.
struct HTTP2StreamTable: Sequence {
    private typealias Storage = [HTTP2StreamID: HTTP2Connection.StreamRecord]

    private var storage: Storage = [:]

    /// The sum of every tracked stream's buffered request-body byte count (`body.count`).
    ///
    /// Maintained on each mutation; equal to `reduce(0) { $0 + $1.value.body.count }` by construction
    /// (RFC 9113 §6.9).
    private(set) var totalBufferedBody = 0

    var count: Int { storage.count }
    var isEmpty: Bool { storage.isEmpty }
    var keys: some Sequence<HTTP2StreamID> { storage.keys }

    subscript(id: HTTP2StreamID) -> HTTP2Connection.StreamRecord? {
        get { storage[id] }
        set {
            // Resolve the prior record in the same mutation that installs the new one, so the body
            // delta is exact and the table is touched once on the response-flush / DATA hot path.
            let previous: HTTP2Connection.StreamRecord?
            if let newValue {
                previous = storage.updateValue(newValue, forKey: id)
            }
            else {
                previous = storage.removeValue(forKey: id)
            }
            totalBufferedBody += (newValue?.body.count ?? 0) - (previous?.body.count ?? 0)
        }
    }

    /// Removes and returns the record for `id`, debiting its buffered body from ``totalBufferedBody``.
    @discardableResult
    mutating func removeValue(forKey id: HTTP2StreamID) -> HTTP2Connection.StreamRecord? {
        let removed = storage.removeValue(forKey: id)
        totalBufferedBody -= removed?.body.count ?? 0
        return removed
    }

    func makeIterator() -> Dictionary<HTTP2StreamID, HTTP2Connection.StreamRecord>.Iterator {
        storage.makeIterator()
    }
}
