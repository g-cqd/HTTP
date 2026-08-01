//
//  HTTP3StreamExit.swift
//  HTTPServer
//
//  How a driver finished with one HTTP/3 request stream (audit R5-P0c).
//
//  This exists to make forgetting to retire a stream *unspellable*. Every driver of a request stream
//  runs inside ``HTTPServer/withHTTP3RequestStream(_:in:_:)``, whose body must return one of these — so
//  there is no `return` that skips the retirement, and no early exit that leaves the engine holding a
//  stream the wire has already given up on. A `defer` could not do the job: retirement is `async`, and
//  Swift's `defer` cannot await.
//
//  Two cases, because there are exactly two things a driver can have done: answered the request, or
//  abandoned it with an RFC 9114 §8.1 code. Which of the two it is decides the code the peer is told,
//  and nothing else — the sweep on the way out is identical, which is the point.
//
//  Standards: RFC 9114 §4.1 (request streams), §8.1 (error codes).
//

internal import HTTP3

/// How a request stream's driver ended, and therefore what the peer is told if anything is left.
enum HTTP3StreamExit: Sendable, Equatable {
    /// The request was answered and the stream closed normally (RFC 9114 §4.1).
    ///
    /// Nothing should be left to retire — the engine drops a stream's record as it encodes the
    /// response — so the sweep on the way out proves that rather than assuming it. If anything *is*
    /// left, it is a stream the peer never got an answer on, and H3_NO_ERROR is the honest code.
    case answered

    /// The stream ended without a complete answer and must be abandoned with `errorCode` (§8.1).
    ///
    /// H3_REQUEST_REJECTED promises the peer the request was not processed and may be safely retried;
    /// H3_REQUEST_INCOMPLETE says the opposite. Picking between them is the caller's job because only
    /// the caller knows whether the head reached the responder.
    case abandoned(errorCode: UInt64)

    /// The QUIC application error code this ending resets the stream with, if anything is left of it.
    var errorCode: UInt64 {
        switch self {
            case .answered:
                HTTP3ErrorCode.h3NoError.rawValue
            case .abandoned(let code):
                code
        }
    }
}
