//
//  StreamingFlag.swift
//  HTTPServerTests
//
//  Records whether the body a responder was handed was still a ``RequestBody/stream(_:)``. A
//  middleware that collects the body forwards `.collected(_:)` instead, so this is the direct
//  observation of "installing this middleware did not un-stream the request".
//

/// Records the streaming shape of the request body a responder received.
actor StreamingFlag {
    private(set) var wasStreaming: Bool?

    /// Records that the responder received a streamed (`true`) or buffered (`false`) body.
    func record(_ streaming: Bool) {
        wasStreaming = streaming
    }
}
