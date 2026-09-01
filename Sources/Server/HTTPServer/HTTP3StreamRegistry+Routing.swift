//
//  HTTP3StreamRegistry+Routing.swift
//  HTTPServer
//
//  Splitting one engine event batch across the streams it names (audit addendum P0.3). The engine is
//  connection-scoped and its output is addressed by stream id, not by whichever stream's bytes provoked
//  it: RFC 9204 §2.1.2 makes that routine, because an encoder-stream insert unblocks a field section
//  belonging to a *request* stream, so feeding the encoder stream surfaces that request stream's
//  `request` event.
//
//  This lives on the registry rather than on the driver because "where does output for this stream go"
//  is precisely what the registry answers, and because the *caller* must not be able to hold a batch
//  between the engine producing it and the registry filing it. That gap was the R5-P0b race: the engine
//  cleared a stream's blocked state, and only afterwards — a suspension point later, on a different
//  task — did the event reach the registry. A driver asking "is this stream still blocked?" in between
//  was told no, retired the entry, and the event then arrived for a stream nobody was tracking.
//
//  So routing is called from inside the engine actor, in the same critical section as the receive that
//  produced the batch. The engine's own isolation is then what orders it against every other engine
//  operation, including the end-of-driving decision — the ordering is a property of where the code runs,
//  not of how the scheduler happened to interleave two tasks.
//
//  Standards: RFC 9114 §5.2 (GOAWAY is connection-scoped), §8.1 (H3_EXCESSIVE_LOAD); RFC 9204 §2.1.2.
//

internal import HTTP3
internal import HTTPCore

extension HTTP3StreamRegistry {
    /// Files each event against the stream its id names, and returns the ones belonging to `owner`.
    ///
    /// Connection-scoped events — GOAWAY, whose id is a stream *limit* rather than a stream to act on
    /// (RFC 9114 §5.2) — stay with the caller.
    ///
    /// A batch refused by its target's bounded mailbox is *not* dropped: the target's id comes back in
    /// `overflowed` for the caller to run through stream retirement, which resets it with
    /// H3_EXCESSIVE_LOAD (RFC 9114 §8.1, CWE-770). Losing a `request` or a body chunk is a correctness
    /// fault, not a throttle — the peer would get neither a response nor a reset.
    ///
    /// - Returns: the events belonging to `owner`, and the ids whose mailbox refused their batch.
    func route(
        _ events: [HTTP3Connection.Event],
        owner: QUICStreamID
    ) -> (own: [HTTP3Connection.Event], overflowed: [QUICStreamID]) {
        var own: [HTTP3Connection.Event] = []
        var foreign: [QUICStreamID: [HTTP3Connection.Event]] = [:]
        var order: [QUICStreamID] = []
        for event in events {
            guard let id = Self.owningStream(of: event), id != owner else {
                own.append(event)
                continue
            }
            if foreign[id] == nil { order.append(id) }
            foreign[id, default: []].append(event)
        }
        var overflowed: [QUICStreamID] = []
        for id in order {
            // The deposit cannot park waiting for room. Its caller is the engine actor, so suspending
            // it on another stream's application progress would block every stream on the connection —
            // cross-stream head-of-line blocking, the thing HTTP/3 exists to remove — and can deadlock
            // against a consumer that is itself waiting on the engine. It fails closed instead.
            if case .overflow = deposit(foreign[id] ?? [], for: id) {
                overflowed.append(id)
            }
        }
        return (own, overflowed)
    }

    /// The request stream an event belongs to, or nil when it is connection-scoped.
    ///
    /// RFC 9114 §5.2 — GOAWAY carries the stream *limit* the peer will stop at, not a stream to deliver
    /// anything on, so it is the one event with no owner.
    static func owningStream(of event: HTTP3Connection.Event) -> QUICStreamID? {
        switch event {
            case .request(let id, _, _),
                .requestHead(let id, _),
                .requestBodyChunk(let id, _),
                .requestEnd(let id),
                .extendedConnect(let id, _, _),
                .tunnelData(let id, _),
                .tunnelClosed(let id):
                id
            case .goAway:
                nil
        }
    }
}
