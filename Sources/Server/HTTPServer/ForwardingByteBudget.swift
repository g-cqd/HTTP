//
//  ForwardingByteBudget.swift
//  HTTPServer
//
//  A pass-through octet budget for a streamed request body: it hands each chunk on to the consumer
//  and charges it against a hard limit, ending the body the moment the limit is crossed. The
//  alternative — collect the whole body, then compare its size — buffers the exact payload it is
//  meant to refuse (CWE-400) and turns every guarded route into a buffered one. Counting in the
//  forwarding path costs one addition per chunk and retains nothing beyond the chunk in flight.
//

internal import Synchronization

/// Forwards request-body chunks one at a time while charging their octets against a hard limit.
///
/// `@unchecked Sendable` over two clearly separated pieces of state: the accounting a consumer reads
/// from another isolation domain lives under a ``Mutex``, and the source iterator is advanced by
/// exactly one consumer. `AsyncIteratorProtocol` already mandates that single consumer, and the
/// `AsyncStream(unfolding:)` that ``makeBody()`` returns calls its producer strictly serially, so
/// there is never more than one `nextChunk()` in flight — the invariant `nonisolated(unsafe)` states.
final class ForwardingByteBudget: @unchecked Sendable {
    /// How much has been forwarded, and whether the budget was crossed.
    private struct Accounting {
        var forwarded = 0
        var tripped = false
    }

    private let accounting = Mutex(Accounting())

    /// The source iterator — see the type's note for why it is not lock-guarded (a `mutating async`
    /// call cannot hold a lock across its suspension anyway).
    nonisolated(unsafe) private var iterator: HTTPRequestBodyStream.Iterator

    /// The maximum number of octets that may be forwarded (a negative limit is read as zero).
    let limit: Int

    deinit {
        // No teardown beyond ARC; abandoning the iterator releases the source stream.
    }

    /// Creates a budget forwarding from `stream`, allowing at most `limit` octets through.
    init(forwarding stream: HTTPRequestBodyStream, limit: Int) {
        iterator = stream.makeAsyncIterator()
        self.limit = max(0, limit)
    }

    /// Whether a chunk crossed ``limit`` — the caller answers `413` (RFC 9110 §15.5.14).
    var isExceeded: Bool { accounting.withLock(\.tripped) }

    /// How many octets were forwarded to the consumer.
    var forwardedCount: Int { accounting.withLock(\.forwarded) }

    /// The next chunk, or nil at end of body — or as soon as forwarding it would cross ``limit``.
    ///
    /// Ending the stream rather than yielding the crossing chunk is the fail-closed half: the
    /// consumer never sees an octet past the budget, and the source is left unread from that point.
    func nextChunk() async -> [UInt8]? {
        guard !isExceeded, let chunk = await iterator.next() else {
            return nil
        }
        return accounting.withLock { state in
            // `limit - state.forwarded` is non-negative by construction (`forwarded <= limit` always
            // holds), so this cannot overflow the way `forwarded + chunk.count` could.
            guard chunk.count <= limit - state.forwarded else {
                state.tripped = true
                return nil
            }
            state.forwarded += chunk.count
            return chunk
        }
    }

    /// A ``RequestBody`` that draws from this budget — the body handed to the next responder.
    func makeBody() -> RequestBody {
        let produce: @Sendable () async -> [UInt8]? = { await self.nextChunk() }
        return .stream(HTTPRequestBodyStream(AsyncStream(unfolding: produce)))
    }
}
