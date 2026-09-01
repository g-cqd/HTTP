//
//  ContentEncodingError.swift
//  HTTPServer
//
//  Why an incremental content coding (RFC 9110 §8.4.1) could not continue. Deliberately tiny and
//  typed: a ``ContentEncoderStream`` is driven from inside a response body producer, where the only
//  two honest outcomes are "here are more octets" and "this response is now unfinishable", and a
//  typed `throws` keeps the second from arriving as an untyped surprise the writer has to re-classify.
//

/// Why an incremental content coding could not continue (RFC 9110 §8.4.1).
public enum ContentEncodingError: Error, Equatable, Sendable {
    /// The backend rejected the input or could not produce output — the response cannot be completed.
    ///
    /// There is no recovery: a `Content-Encoding` header is already on the wire, so the octets emitted
    /// so far are an incomplete coded stream and the only correct end is to fail the body and let the
    /// engine close the connection rather than deliver something a decoder would accept as whole.
    case encoderFailed

    /// ``ContentEncoderStream/finish()`` already ran; the stream cannot take more input.
    case streamFinished
}
