//
//  QPACKRecentFieldWindow.swift
//  QPACK
//
//  The insert-on-second-use window behind the RFC 9204 §4.3 encoder: a bounded FIFO of fields seen but
//  not yet inserted into the dynamic table. A field earns an insert only by recurring while it is still
//  in the window, which is what keeps unique per-response values (date, etag, content-length) out of a
//  table whose entries every later section pays for.
//
//  Structurally this is the ring-plus-hash-index shape ``QPACKDynamicTable`` uses, at a smaller scale.
//  The window was a plain `[HeaderField]`, so each sighting scanned it (`contains`) and each eviction
//  shifted it (`removeFirst`) — both O(limit), and both paid on exactly the fields the heuristic exists
//  to REJECT, since a unique value misses the whole window every time and then pushes the oldest out.
//  Measured on an 8-field response section with three per-response values, that was 192 field
//  comparisons and 192 element shifts per section, at a window permanently saturated at its 64 entries.
//
//  The position index doubles as the membership test, which is what removes the need for a separate
//  monotonic sequence: a slot is only authoritative for a field while the map still points AT that
//  slot. Forgetting a field blanks its slot, so recycling that slot later cannot drop a field that has
//  since been sighted again — the staleness trap a bare `Set` alongside the ring would fall into.
//

internal import HTTPCore

/// A bounded FIFO of recently sighted, not-yet-inserted fields (RFC 9204 §4.3) — O(1) per operation.
struct QPACKRecentFieldWindow {
    /// Ring of the most recent distinct sightings, oldest at ``next``; a blanked slot holds `nil`.
    private var slots: [HeaderField?]
    /// The slot the next sighting overwrites — equivalently, the oldest live sighting's slot.
    private var next = 0
    /// Field → the slot that currently speaks for it; also the O(1) membership test.
    private var slotOfField: [HeaderField: Int] = [:]

    /// Creates a window retaining at most `limit` distinct sightings.
    ///
    /// `limit` is clamped to at least 1, so a degenerate configuration still records one sighting
    /// rather than trapping on a zero-length ring.
    init(limit: Int) {
        slots = [HeaderField?](repeating: nil, count: max(1, limit))
        slotOfField.reserveCapacity(max(1, limit))
    }

    /// Records a sighting of `field`, returning whether it had already been seen — a repeat worth
    /// inserting into the dynamic table.
    ///
    /// A repeat does NOT refresh the field's position: it stays where it was, so it ages out on the
    /// same schedule as before. That matches the superseded array, which likewise only appended on a
    /// miss, and it keeps a field the encoder cannot yet insert (no room, RFC 9204 §2.1.3) from pinning
    /// the window open indefinitely.
    mutating func recordSighting(of field: HeaderField) -> Bool {
        if slotOfField[field] != nil {
            return true
        }
        // Claim the oldest slot. Whatever it held stops being tracked — but only if that entry still
        // points here, since a forgotten-then-resighted field left this slot behind.
        if let displaced = slots[next], slotOfField[displaced] == next {
            slotOfField[displaced] = nil
        }
        slots[next] = field
        slotOfField[field] = next
        next += 1
        if next == slots.count {
            next = 0
        }
        return false
    }

    /// Drops `field` from the window once it lives in the dynamic table (or is otherwise no longer a
    /// candidate); a field the window does not hold is left alone.
    mutating func forget(_ field: HeaderField) {
        guard let slot = slotOfField.removeValue(forKey: field) else {
            return
        }
        // Blank the slot, so recycling it later cannot drop a fresher sighting of the same field.
        slots[slot] = nil
    }
}
