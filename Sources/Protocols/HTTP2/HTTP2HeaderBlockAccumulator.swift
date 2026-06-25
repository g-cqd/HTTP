//
//  HTTP2HeaderBlockAccumulator.swift
//  HTTP2
//
//  RFC 9113 §6.10 — a header block is one HEADERS frame followed by zero or more CONTINUATION frames,
//  ending at the frame whose END_HEADERS flag is set. No other frame (nor a frame on another stream)
//  may interleave (PROTOCOL_ERROR). This accumulator concatenates the field block fragments and
//  enforces two bounds that defuse the CONTINUATION flood (CVE-2024-27316): a cap on the number of
//  CONTINUATION frames and on the cumulative block size.
//

/// Assembles a HEADERS + CONTINUATION sequence into one header block (RFC 9113 §6.10).
public struct HTTP2HeaderBlockAccumulator {
    private struct Pending {
        let streamID: HTTP2StreamID
        var fragment: [UInt8]
        var continuationCount: Int
    }

    private var pending: Pending?
    private let maxContinuationFrames: Int
    private let maxBlockSize: Int

    /// Creates an accumulator bounded by `maxContinuationFrames` frames and `maxBlockSize` octets.
    public init(maxContinuationFrames: Int, maxBlockSize: Int) {
        self.maxContinuationFrames = maxContinuationFrames
        self.maxBlockSize = maxBlockSize
    }

    /// The result of feeding one HEADERS or CONTINUATION frame.
    public enum Outcome: Sendable, Equatable {
        /// END_HEADERS was set; the complete header block is ready for HPACK decoding.
        case complete(HTTP2StreamID, [UInt8])

        /// More CONTINUATION frames are required before the block is whole.
        case needsContinuation
    }

    /// Whether a header block is open, awaiting CONTINUATION frames (RFC 9113 §6.10).
    public var isExpectingContinuation: Bool { pending != nil }

    /// The stream whose CONTINUATION frames are expected, if any.
    public var expectedStream: HTTP2StreamID? { pending?.streamID }

    /// Begins a header block from a HEADERS frame's field block `fragment` (RFC 9113 §6.2).
    public mutating func begin(
        streamID: HTTP2StreamID,
        fragment: some Collection<UInt8>,
        endHeaders: Bool
    ) throws(HTTP2Error) -> Outcome {
        guard pending == nil else {
            throw .connection(.internalError, "HEADERS began while a header block was still open")
        }
        guard fragment.count <= maxBlockSize else {
            throw .connection(.enhanceYourCalm, "header block exceeds the configured size bound")
        }
        if endHeaders {
            return .complete(streamID, Array(fragment))
        }
        pending = Pending(streamID: streamID, fragment: Array(fragment), continuationCount: 0)
        return .needsContinuation
    }

    /// Appends a CONTINUATION frame's `fragment` to the open block (RFC 9113 §6.10).
    ///
    /// Fails closed if no block is open, the stream differs, too many CONTINUATION frames arrive
    /// (ENHANCE_YOUR_CALM — the CVE-2024-27316 flood), or the cumulative block is too large.
    public mutating func append(
        streamID: HTTP2StreamID,
        fragment: some Collection<UInt8>,
        endHeaders: Bool
    ) throws(HTTP2Error) -> Outcome {
        guard var current = pending else {
            throw .connection(.protocolError, "CONTINUATION without an open header block")
        }
        guard current.streamID == streamID else {
            throw .connection(.protocolError, "CONTINUATION on a different stream")
        }
        current.continuationCount += 1
        guard current.continuationCount <= maxContinuationFrames else {
            throw .connection(.enhanceYourCalm, "too many CONTINUATION frames")
        }
        guard current.fragment.count + fragment.count <= maxBlockSize else {
            throw .connection(.enhanceYourCalm, "header block exceeds the configured size bound")
        }
        current.fragment.append(contentsOf: fragment)
        if endHeaders {
            pending = nil
            return .complete(streamID, current.fragment)
        }
        pending = current
        return .needsContinuation
    }
}
