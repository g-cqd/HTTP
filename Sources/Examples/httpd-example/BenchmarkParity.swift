//
//  BenchmarkParity.swift
//  httpd-example
//
//  The response bodies the comparative benchmark (`Benchmarking/Bench/run.sh`) requires every server
//  in the field to return BYTE-FOR-BYTE, and the one response constructor that does not re-encode
//  them on each request.
//
//  Two harness defects are answered here.
//
//  1. NOT THE SAME BYTES. The field's `GET /` handlers each answer with their own name ("Hello from
//     the Rust baseline.\n", "Hello from the Go baseline.\n", …) — different lengths, different
//     content. A throughput comparison on a route where the servers return different payloads is not
//     a comparison. `/plaintext` replaces `/` as the framework-floor scenario and is identical
//     everywhere; the harness now proves that by fetching each route from each server and diffing
//     the bytes before it starts timing.
//
//  2. NOT THE SAME WORK. `ServerResponse.text(_: String)` calls `Array(body.utf8)`, so serving a
//     hoisted `String` still allocated and copied the body on every request. Every peer serves these
//     routes from a pre-encoded constant. ``text(_:)`` takes the already-encoded bytes, so the
//     `[UInt8]` is retained rather than copied and the remaining per-request work — building the
//     `Content-Type` field — is what the peers also do.
//

import HTTPCore
import HTTPServer

/// The byte-identical benchmark bodies, and a response constructor that does not re-encode them.
enum BenchmarkParity {
    /// The framework-floor body, identical across every server in the comparison.
    ///
    /// Deliberately not a server's own greeting: `/` is each server's identity page and is excluded
    /// from the measured scenario set precisely because those bodies differ.
    static let plaintextBody = "Hello, World!"

    /// The `/json` body — the encoded object, byte-identical across the field (RFC 8259).
    static let jsonBody = #"{"message":"Hello, World!"}"#

    /// The `/payload` body — 32 × 32 B = 1024 B of compressible text, byte-identical across the field.
    static let payloadBody = String(repeating: "from-scratch swift http server. ", count: 32)

    /// A `text/plain; charset=utf-8` response over ALREADY-ENCODED bytes (RFC 9110 §8.3).
    ///
    /// The `[UInt8]` is passed through, so a hoisted body costs a retain instead of the allocation
    /// and copy that `ServerResponse.text(_: String)` performs on every call.
    static func text(_ body: [UInt8]) -> ServerResponse {
        var fields = HTTPFields()
        _ = fields.setValue("text/plain; charset=utf-8", for: .contentType)
        return ServerResponse(HTTPResponse(status: .ok, headerFields: fields), body: body)
    }
}
