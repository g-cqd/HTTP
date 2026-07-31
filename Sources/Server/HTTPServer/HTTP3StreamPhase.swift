//
//  HTTP3StreamPhase.swift
//  HTTPServer
//
//  Which read an HTTP/3 request stream is waiting on, and therefore which deadline bounds it and what
//  the peer is told when that deadline lapses (audit addendum P0.5). The HTTP/1.1 reader has had
//  phase-scoped Slowloris deadlines since `HTTPLimits.headerReadTimeout` / `idleTimeout` existed; a
//  QUIC request stream had none at all.
//
//  Standards: the Slowloris defense of RFC 9112 §9.3 applied to RFC 9114 §4.1 request streams; the
//  error codes are RFC 9114 §8.1. CWE-400 (uncontrolled resource consumption).
//

internal import HTTP3

/// The read an HTTP/3 request stream is currently blocked on.
enum HTTP3StreamPhase: Sendable, Equatable {
    /// Waiting for the request HEADERS — nothing has been handed to the application yet.
    case header
    /// Waiting for more request DATA, or for the FIN that ends the body.
    case body

    /// The QUIC application error code the stream is reset with when this phase's deadline lapses
    /// (RFC 9114 §8.1).
    ///
    /// The distinction is not cosmetic: `H3_REQUEST_REJECTED` promises the peer that the request was
    /// **not processed** and may be retried safely on another connection, which is only true while the
    /// head has not reached the responder. Once the body is being read the head has been dispatched,
    /// so the honest code is `H3_REQUEST_INCOMPLETE`.
    var errorCode: UInt64 {
        switch self {
            case .header:
                HTTP3ErrorCode.h3RequestRejected.rawValue
            case .body:
                HTTP3ErrorCode.h3RequestIncomplete.rawValue
        }
    }
}
