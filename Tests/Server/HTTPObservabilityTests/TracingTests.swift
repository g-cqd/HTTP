//
//  TracingTests.swift
//  HTTPObservabilityTests
//
//  The swift-distributed-tracing span-per-request bridge, against the official `InMemoryTracer`: a
//  request opens one `.server` span named by method, tagged with the OpenTelemetry HTTP attributes, with
//  a 5xx marked errored and a 2xx left clean. The `HTTPFieldsExtractor` reads W3C `traceparent` off the
//  carrier — the inbound half of trace-context propagation.
//

import HTTPCore
import HTTPServer
import InMemoryTracing
import Instrumentation
import Testing
import Tracing

@testable import HTTPObservability

@Suite("HTTPObservability — distributed tracing", .serialized)
struct TracingTests {
    /// One process-wide tracer bootstrap (a `static let` runs exactly once, thread-safe).
    static let tracer: InMemoryTracer = {
        let tracer = InMemoryTracer()
        InstrumentationSystem.bootstrap(tracer)
        return tracer
    }()

    @Test("opens a .server span named by method, tags OTel attributes, marks 5xx errored")
    func serverSpanErroredFor5xx() async throws {
        let tracer = Self.tracer
        tracer.clearAll(includingActive: true)
        _ = await TracingMiddleware()
            .respond(
                to: request(.post, "/boom"),
                body: [],
                next: StubResponder(status: .internalServerError)
            )

        let span = try #require(tracer.popFinishedSpans().first)
        #expect(span.operationName == "POST")
        guard case .server = span.kind else {
            Issue.record("expected a .server span kind")
            return
        }
        guard case .error = span.status?.code else {
            Issue.record("expected an .error span status for a 5xx response")
            return
        }
        #expect(span.attributes.count >= 3)  // method + path + status_code
    }

    @Test("a 2xx response leaves the span unerrored")
    func successSpanUnerrored() async throws {
        let tracer = Self.tracer
        tracer.clearAll(includingActive: true)
        _ = await TracingMiddleware()
            .respond(
                to: request(.get, "/ok"),
                body: [],
                next: StubResponder(status: .ok)
            )

        let span = try #require(tracer.popFinishedSpans().first)
        #expect(span.operationName == "GET")
        if case .error = span.status?.code {
            Issue.record("a 2xx response must not error the span")
        }
    }

    @Test("the extractor reads a W3C traceparent header off the carrier (trace-context round-trip)")
    func extractorReadsTraceparent() throws {
        let name = try #require(HTTPFieldName("traceparent"))
        let traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        var fields = HTTPFields()
        _ = fields.append(traceparent, for: name)

        let extractor = HTTPFieldsExtractor()
        #expect(extractor.extract(key: "traceparent", from: fields) == traceparent)
        #expect(extractor.extract(key: "absent", from: fields) == nil)
    }

    private func request(_ method: HTTPMethod, _ path: String) -> HTTPRequest {
        HTTPRequest(method: method, scheme: "https", authority: "x", path: path)
    }
}
