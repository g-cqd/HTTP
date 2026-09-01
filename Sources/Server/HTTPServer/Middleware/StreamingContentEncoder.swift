//
//  StreamingContentEncoder.swift
//  HTTPServer
//
//  The opt-in half of the content-coding seam: a ``ContentEncoder`` that can also code incrementally.
//  Kept as a refinement rather than folded into ``ContentEncoder`` so every existing encoder — in this
//  package and in a consumer's — keeps compiling and keeps working, and so "can this coding stream?"
//  is a conformance a reader can see rather than a method that might return nil.
//
//  A backend that cannot stream must decline here. It must NOT buffer the body and call its one-shot
//  encoder: that would reintroduce, on the streaming path specifically, the unbounded retention the
//  streaming path exists to remove — a 4 GiB download would become a 4 GiB allocation. Declining costs
//  the client the coding; buffering costs the server the process.
//

/// A ``ContentEncoder`` that can also code a body incrementally (RFC 9110 §8.4.1).
public protocol StreamingContentEncoder: ContentEncoder {
    /// A fresh encode stream, or nil when this build's backend has no incremental form.
    ///
    /// Returning nil means the response is streamed **unencoded** — never buffered and coded whole.
    func makeStream() -> (any ContentEncoderStream)?
}
