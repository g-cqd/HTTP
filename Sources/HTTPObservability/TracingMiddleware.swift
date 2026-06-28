//
//  TracingMiddleware.swift
//  HTTPObservability
//
//  A span-per-request bridge to swift-distributed-tracing (adapted from the sibling ADServe project's
//  ADServeObservability). It extracts any upstream trace context from the request headers (W3C
//  `traceparent`/`tracestate`) so the request joins an existing distributed trace, opens a `.server`-kind
//  span named by the HTTP method, tags it with the OpenTelemetry HTTP attributes, marks a 5xx response as
//  errored, and ends the span when the response is ready. With no tracer bootstrapped
//  (`InstrumentationSystem.bootstrap`) it is a no-op. Install it outermost so it also spans routing
//  failures (404 / 405). The span's task-local context propagates to any instrumented call in a handler.
//

public import HTTPCore
public import HTTPServer
internal import Instrumentation
internal import ServiceContextModule
internal import Tracing

/// Opens a distributed-tracing `.server` span for every request, propagating W3C trace context.
public struct TracingMiddleware: HTTPMiddleware {
    /// Creates the middleware; it observes the globally bootstrapped tracer (a no-op when none is set).
    public init() {
        // No configuration — the tracer comes from InstrumentationSystem.bootstrap.
    }

    /// The request path without its query string.
    ///
    /// Query strings routinely carry tokens/PII and become queryable fields on exported spans (audit F5).
    /// OTel models `url.path` as the path only.
    private static func pathOnly(_ target: String) -> String {
        String(target.prefix { $0 != "?" && $0 != "#" })
    }

    /// Extracts upstream context, opens a `.server` span, tags it, and ends it with the response.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var context = ServiceContext.topLevel
        InstrumentationSystem.instrument.extract(
            request.headerFields, into: &context, using: HTTPFieldsExtractor()
        )
        return await withSpan(request.method.rawValue, context: context, ofKind: .server) { span in
            span.attributes["http.request.method"] = request.method.rawValue
            span.attributes["url.path"] = Self.pathOnly(request.path)
            if let requestID = request.headerFields[.xRequestID] {
                span.attributes["http.request.id"] = requestID
            }
            let response = await next.respond(to: request, body: body)
            let status = Int(response.head.status.code)
            span.attributes["http.response.status_code"] = status
            // OTel: a server span is errored only for 5xx (a 4xx is the client's fault, not the span's).
            if status >= 500 {
                span.setStatus(SpanStatus(code: .error))
            }
            return response
        }
    }
}
