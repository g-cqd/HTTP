//
//  HTTPPriorityTests.swift
//  HTTPCoreTests
//
//  RFC 9218 Priority: parsing urgency / incremental from the field, default fallback for absent /
//  out-of-range / unparseable input, default-omitting serialization, round-trip, and the
//  HTTPRequest.priority accessor.
//

import HTTPCore
import Testing

@Suite("RFC 9218 Priority")
struct HTTPPriorityTests {
    @Test("parses urgency and incremental from the field")
    func parse() {
        let priority = HTTPPriority(field: "u=1, i")
        #expect(priority.urgency == 1)
        #expect(priority.incremental)
    }

    @Test("defaults apply for absent, out-of-range, or unparseable input")
    func defaults() {
        #expect(HTTPPriority(field: "").urgency == 3)
        #expect(HTTPPriority(field: "").incremental == false)
        #expect(HTTPPriority(field: "u=9").urgency == 3)  // out of range → default
        #expect(HTTPPriority(field: "@@@").urgency == 3)  // unparseable → default
    }

    @Test("serializes omitting defaults, and round-trips")
    func serialize() {
        #expect(HTTPPriority(urgency: 5, incremental: true).fieldValue == "u=5, i")
        #expect(HTTPPriority(urgency: 0, incremental: false).fieldValue == "u=0")
        #expect(HTTPPriority(urgency: 3, incremental: false).fieldValue.isEmpty)  // all defaults
        let priority = HTTPPriority(field: "u=2, i")
        #expect(HTTPPriority(field: priority.fieldValue) == priority)
    }

    @Test("HTTPRequest.priority reads the field, nil when absent")
    func requestAccessor() {
        var fields = HTTPFields()
        _ = fields.append("u=0", for: .priority)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        #expect(request.priority?.urgency == 0)

        let bare = HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
        #expect(bare.priority == nil)
    }
}
