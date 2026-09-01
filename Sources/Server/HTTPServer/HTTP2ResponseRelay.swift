//
//  HTTP2ResponseRelay.swift
//  HTTPServer
//
//  The merged-mailbox consumer's handle on one native-streaming response (P6b / RFC 9113 §8.1): the
//  pull permission it grants, and the handoff the producer offers chunks into.
//
//  It exists because the consumer previously held only the permit. Dropping that entry when a stream
//  ended told neither party anything: a relay parked in `waitForGrant()` waited for a grant that would
//  never come, and the producer behind it stayed parked on an offer nobody would ever take — both for
//  the rest of the connection's life. A relay parked in `handoff.next()` was worse: it went on to
//  report a chunk for a stream the engine had already dropped, and `sendBodyChunk` on an unknown stream
//  throws `internalError`, which is CONNECTION-scoped (RFC 9113 §5.4.1), so the consumer closed the
//  whole connection and every sibling stream with it (2026-07-31 fifth review, R5-P0d).
//
//  Both parked positions therefore have to be reachable from the consumer, and pairing the two objects
//  that already exist per streaming response is what makes that possible — no extra allocation, and no
//  second lifetime to remember: the relay entry IS the lifetime.
//

/// The consumer's handle on one in-flight native-streaming response.
struct HTTP2ResponseRelay: Sendable {
    /// The pull permission this relay waits on before taking the producer's next chunk.
    let permit: HTTP2StreamPermit

    /// The one-slot rendezvous the producer offers chunks into and the relay pulls them from.
    let handoff: AsyncHandoff

    /// Ends this relay: the pump stops asking for chunks and the producer stops offering them.
    ///
    /// The two calls cover the two places the pair can be parked — `waitForGrant()` and `offer(_:)` /
    /// `next()` — so whichever it is unwinds now rather than at connection teardown. Failing the
    /// handoff rather than finishing it is deliberate: the response is being abandoned mid-body, and a
    /// producer must observe that as a failure, not as a clean end of stream.
    func abandon() async {
        await permit.revoke()
        await handoff.fail()
    }
}
