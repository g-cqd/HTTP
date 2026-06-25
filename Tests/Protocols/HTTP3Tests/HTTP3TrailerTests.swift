//
//  HTTP3TrailerTests.swift
//  HTTP3Tests
//
//  RFC 9114 §4.3 — a trailing HEADERS block (trailers) is decoded for validity and then discarded, but
//  it MUST still obey the field rules: no pseudo-header fields (§4.3) and lowercase names only (§4.2).
//  A malformed trailer is a stream error (H3_MESSAGE_ERROR), exactly as on the HTTP/2 path — this is the
//  parity for the shared `RequestMapper.validateTrailers` gate. Boundary/negative (mutation-resistant).
//

import HTTPCore
import HTTPTestSupport
import QPACK
import Testing

@testable import HTTP3

@Suite("RFC 9114 §4.3 — HTTP/3 trailer validation", .tags(.mutation, .conformance))
struct HTTP3TrailerTests: HTTP3WireFixtures {
    private static let stream = QUICStreamID(0)  // client-initiated bidirectional request stream

    /// A trailing HEADERS block carrying a forbidden field is a stream H3_MESSAGE_ERROR.
    ///
    /// Each case (a pseudo-header, an uppercase name) removes a distinct guard if its check regresses.
    @Test(
        "a malformed trailer field is a stream H3_MESSAGE_ERROR (RFC 9114 §4.3/§4.2)",
        arguments: [
            (label: "a pseudo-header field", field: HeaderField(name: ":method", value: "GET")),
            (label: "an uppercase field name", field: HeaderField(name: "Uppercase", value: "v"))
        ] as [(label: String, field: HeaderField)])
    func malformedTrailerIsRejected(_ testCase: (label: String, field: HeaderField)) throws {
        var connection = HTTP3Connection()
        // The request HEADERS opens the stream; the second HEADERS block is the trailers.
        let request = frame(.headers, requestFieldSection())
        let trailers = frame(.headers, fieldSection([testCase.field]))
        _ = try connection.receive(Self.stream, request + trailers, fin: true)
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3MessageError.rawValue)
    }

    /// Valid lowercase trailers must NOT be rejected — the request and its body are still delivered.
    ///
    /// Guards against an over-broad validator that rejects every trailing block.
    @Test("valid lowercase trailers are accepted and the request is delivered (§4.3)")
    func validTrailersAreAccepted() throws {
        var connection = HTTP3Connection()
        let body = Array("hi".utf8)
        let request = frame(.headers, requestFieldSection(method: "POST")) + frame(.data, body)
        let trailer = HeaderField(name: "x-checksum", value: "abc")
        let trailers = frame(.headers, fieldSection([trailer]))
        let events = try connection.receive(Self.stream, request + trailers, fin: true)
        #expect(resetStreamCode(&connection) == nil)
        guard case .request(_, _, let delivered) = events.first else {
            Issue.record("expected the request to be delivered after valid trailers")
            return
        }
        #expect(delivered == body)
    }
}
