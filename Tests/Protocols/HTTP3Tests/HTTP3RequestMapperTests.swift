//
//  HTTP3RequestMapperTests.swift
//  HTTP3Tests
//
//  RED→GREEN driver for RFC 9114 §4.3.1 request mapping — the absence rules the h3spec
//  "mandatory pseudo-header fields are absent [HTTP/3 4.1.3]" case measures. A request missing
//  `:method`, `:scheme`, or `:path` is malformed, and so is an "http"/"https" request carrying
//  neither an `:authority` pseudo-header nor a `Host` field (§4.3.1: a scheme with a mandatory
//  authority component requires one of them, non-empty). Every violation is a stream error of type
//  H3_MESSAGE_ERROR (§4.1.2), never a connection error — h3spec observes it as RESET_STREAM.
//

import HTTPCore
import Testing

@testable import HTTP3

@Suite("RFC 9114 §4.3.1 — mandatory request pseudo-headers")
struct HTTP3RequestMapperTests {
    private let stream = QUICStreamID(0)

    /// Maps `fields` and returns the thrown ``HTTP3Error``, or nil when the request is accepted.
    private func mappingError(_ fields: [HeaderField]) -> HTTP3Error? {
        do {
            _ = try HTTP3RequestMapper.makeRequest(from: fields, streamID: stream)
            return nil
        }
        catch {
            return error
        }
    }

    /// The malformed absence shapes: each is one mandatory element missing (RFC 9114 §4.3.1).
    ///
    /// The fourth row is byte-for-byte what h3spec's 4.1.3 case decodes to (`illegalHeader0`:
    /// QPACK static indexes 17/23/1): `:method`+`:scheme`+`:path` with no `:authority` and no
    /// `Host` — an "https" request without its mandatory authority component.
    private static let absentMandatory: [[HeaderField]] = [
        [
            HeaderField(name: ":scheme", value: "https"),
            HeaderField(name: ":path", value: "/")
        ],
        [
            HeaderField(name: ":method", value: "GET"),
            HeaderField(name: ":path", value: "/")
        ],
        [
            HeaderField(name: ":method", value: "GET"),
            HeaderField(name: ":scheme", value: "https")
        ],
        [
            HeaderField(name: ":method", value: "GET"),
            HeaderField(name: ":scheme", value: "https"),
            HeaderField(name: ":path", value: "/")
        ],
        [
            HeaderField(name: ":method", value: "GET"),
            HeaderField(name: ":scheme", value: "http"),
            HeaderField(name: ":path", value: "/")
        ],
        [
            HeaderField(name: ":method", value: "GET"),
            HeaderField(name: ":scheme", value: "https"),
            HeaderField(name: ":authority", value: ""),
            HeaderField(name: ":path", value: "/")
        ]
    ]

    @Test(
        "an absent mandatory pseudo-header is a stream H3_MESSAGE_ERROR (§4.1.2 / §4.3.1)",
        arguments: absentMandatory)
    func absentMandatoryPseudoHeaderIsMalformed(fields: [HeaderField]) {
        let error = mappingError(fields)
        #expect(error?.code == HTTP3ErrorCode.h3MessageError.rawValue)
        #expect(error?.streamID == stream, "malformed is a STREAM error, not a connection error")
    }

    @Test("a non-empty :authority satisfies the https authority requirement (§4.3.1)")
    func authoritySatisfiesRequirement() throws {
        let (request, _) = try HTTP3RequestMapper.makeRequest(
            from: [
                HeaderField(name: ":method", value: "GET"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "example.com"),
                HeaderField(name: ":path", value: "/")
            ],
            streamID: stream
        )
        #expect(request.authority == "example.com")
    }

    @Test("a non-empty Host field satisfies the https authority requirement (§4.3.1)")
    func hostFieldSatisfiesRequirement() throws {
        let (request, _) = try HTTP3RequestMapper.makeRequest(
            from: [
                HeaderField(name: ":method", value: "GET"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":path", value: "/"),
                HeaderField(name: "host", value: "example.com")
            ],
            streamID: stream
        )
        #expect(request.headerFields[.host] == "example.com")
    }
}
