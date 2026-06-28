//
//  LoggingTests.swift
//  HTTPObservabilityTests
//
//  The swift-log structured access sink: one `info` entry per response, carrying method / path / status /
//  duration_ms / request_id as metadata fields a backend can index.
//

import HTTPCore
import HTTPObservability
import HTTPServer
import Logging
import Testing

@Suite("HTTPObservability — structured access log")
struct LoggingTests {
    @Test("logs one info entry with method, path, status, duration_ms, and request_id metadata")
    func logsStructuredEntry() async {
        let store = CapturingLogHandler.Store()
        let logger = Logger(label: "test.access") { _ in CapturingLogHandler(store) }

        var fields = HTTPFields()
        _ = fields.append("req-123", for: .xRequestID)
        let request = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/items", headerFields: fields
        )
        _ = await LoggingMiddleware(logger)
            .respond(to: request, body: [], next: StubResponder(status: .created))

        let entries = store.entries
        #expect(entries.count == 1)
        guard let entry = entries.first else {
            return
        }
        #expect(entry.level == .info)
        #expect(entry.metadata["method"] == .string("GET"))
        #expect(entry.metadata["path"] == .string("/items"))
        #expect(entry.metadata["status"] == .string("201"))
        #expect(entry.metadata["request_id"] == .string("req-123"))
        #expect(entry.metadata["duration_ms"] != nil)  // a measured latency is always attached
    }

    @Test("the access log records the path without its query string (audit F5)")
    func redactsQueryStringFromPath() async {
        let store = CapturingLogHandler.Store()
        let logger = Logger(label: "test.access") { _ in CapturingLogHandler(store) }
        let request = HTTPRequest(
            method: .get,
            scheme: "https",
            authority: "x",
            path: "/search?token=secret&q=hi",
            headerFields: HTTPFields()
        )
        _ = await LoggingMiddleware(logger)
            .respond(to: request, body: [], next: StubResponder(status: .ok))
        // The query string (which routinely carries tokens/PII) must not reach the log sink.
        #expect(store.entries.first?.metadata["path"] == .string("/search"))
    }
}
