//
//  ExpectDisposition.swift
//  HTTPServer
//
//  RFC 9110 §10.1.1 — what a request's `Expect` calls for, decided once the head has parsed but before
//  the body is read. The only defined expectation is `100-continue`: on an HTTP/1.1 request that will
//  send a body, the server sends an interim `100 Continue` so a waiting client proceeds; any other
//  expectation it cannot meet is `417 Expectation Failed`. Pulling the decision into a pure, non-generic
//  classifier keeps it unit-testable without driving the whole read loop.
//

internal import HTTP1
internal import HTTPCore

/// The disposition of a request's `Expect` field (RFC 9110 §10.1.1).
enum ExpectDisposition: Equatable {
    /// No `Expect`, or it does not apply (HTTP/1.0, or no body to await) — read the body normally.
    case proceed
    /// `100-continue` on an HTTP/1.1 request that will send a body — send an interim `100 Continue`.
    case sendContinue
    /// An expectation the server cannot meet — respond `417 Expectation Failed` and close.
    case failed

    /// The interim `100 Continue` status line (RFC 9110 §15.2.1) — no headers, no body.
    static let continueLine = Array("HTTP/1.1 100 Continue\r\n\r\n".utf8)

    /// Classifies the disposition of a request's `Expect` field.
    ///
    /// `100-continue` (RFC 9110 §10.1.1) is the only defined expectation; it applies to an HTTP/1.1
    /// request that will send a body, and anything else is `417`.
    static func evaluate(_ head: RequestHead) -> Self {
        let values = head.request.headerFields.values(for: .expect)
        guard !values.isEmpty else {
            return .proceed
        }
        for value in values {
            for token in value.split(separator: ",") {
                let normalized = String(token.filter { $0 != " " && $0 != "\t" }).lowercased()
                guard normalized == "100-continue" else {
                    return .failed  // an unsupported expectation (RFC 9110 §10.1.1)
                }
            }
        }
        let expectsBody: Bool
        switch head.framing {
            case .none:
                expectsBody = false
            case .contentLength(let length):
                expectsBody = length > 0
            case .chunked:
                expectsBody = true
        }
        // 100-continue is an HTTP/1.1 mechanism and is moot when no body will follow.
        guard head.version == .http11, expectsBody else {
            return .proceed
        }
        return .sendContinue
    }
}
