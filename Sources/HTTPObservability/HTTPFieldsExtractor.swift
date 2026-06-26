//
//  HTTPFieldsExtractor.swift
//  HTTPObservability
//
//  The swift-distributed-tracing `Extractor` over HTTP's `HTTPFields`. The instrument reads propagation
//  headers (W3C Trace Context `traceparent`/`tracestate`, B3, …) by name to rebuild an upstream
//  `ServiceContext`, so an incoming request joins an existing distributed trace. The lookup is trap-free:
//  a key that is not a valid field-name token yields nil rather than faulting.
//

internal import HTTPCore
internal import Instrumentation

/// Reads a propagation header by name off an `HTTPFields` carrier (e.g. W3C `traceparent`).
struct HTTPFieldsExtractor: Extractor {
    func extract(key: String, from carrier: HTTPFields) -> String? {
        guard let name = HTTPFieldName(key) else {
            return nil
        }
        return carrier[name]
    }
}
