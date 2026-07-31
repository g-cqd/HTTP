//
//  HTTPLimitsError.swift
//  HTTPCore
//
//  What `HTTPLimits.init(validating:)` throws. The clamping initializer silently repairs an illegal
//  value; this is the entry point for a caller — a configuration file loader, a command-line parser —
//  that would rather be told its input was wrong than have it quietly changed underneath.
//

/// Why a set of limits was refused.
///
/// Every case names the limit at fault, so a loader can point at the line of configuration that
/// produced it rather than reporting "invalid limits".
public enum HTTPLimitsError: Error, Equatable, Sendable {
    /// A limit falls outside the range its standard fixes.
    ///
    /// `allowed` is that range rendered for a diagnostic — the authoritative definition lives on the
    /// limit's own documentation, together with the RFC or CVE that fixes it.
    case outOfRange(limit: Limit, allowed: String)

    /// Two limits are each legal alone but cannot hold together.
    ///
    /// A cross-field invariant: `limit` must not exceed `mustNotExceed`, and no per-field range can
    /// express that because either field alone is within its own bounds.
    case incoherent(limit: Limit, mustNotExceed: Limit)

    /// A limit that validation can name.
    ///
    /// A closed enumeration rather than a string, so a caller can `switch` over what failed and the
    /// compiler tells it when a new limit joins the set.
    public enum Limit: String, Sendable, CaseIterable {
        /// ``HTTPLimits/maxRequestLineLength``.
        case maxRequestLineLength
        /// ``HTTPLimits/maxFieldSize``.
        case maxFieldSize
        /// ``HTTPLimits/maxHeaderListSize``.
        case maxHeaderListSize
        /// ``HTTPLimits/maxFieldCount``.
        case maxFieldCount
        /// ``HTTPLimits/maxBodySize``.
        case maxBodySize
        /// ``HTTPLimits/maxWebSocketMessageSize``.
        case maxWebSocketMessageSize
        /// ``HTTPLimits/maxDecompressedBodySize``.
        case maxDecompressedBodySize
        /// ``HTTPLimits/maxDecompressionRatio``.
        case maxDecompressionRatio
        /// ``HTTPLimits/maxDecompressionLayers``.
        case maxDecompressionLayers
        /// ``HTTPLimits/maxConcurrentStreams``.
        case maxConcurrentStreams
        /// ``HTTPLimits/maxFrameSize``.
        case maxFrameSize
        /// ``HTTPLimits/headerTableSize``.
        case headerTableSize
        /// ``HTTPLimits/maxContinuationFrames``.
        case maxContinuationFrames
        /// ``HTTPLimits/maxStreamResetsPerInterval``.
        case maxStreamResetsPerInterval
        /// ``HTTPLimits/maxControlFramesPerInterval``.
        case maxControlFramesPerInterval
        /// ``HTTPLimits/maxQueuedInboundBytes``.
        case maxQueuedInboundBytes
        /// ``HTTPLimits/maxQueuedInboundChunks``.
        case maxQueuedInboundChunks
        /// ``HTTPLimits/maxQueuedBroadcasts``.
        case maxQueuedBroadcasts
        /// ``HTTPLimits/streamReceiveWindow``.
        case streamReceiveWindow
        /// ``HTTPLimits/connectionReceiveWindow``.
        case connectionReceiveWindow
        /// ``HTTPLimits/bodyConsumptionTimeout``.
        case bodyConsumptionTimeout
        /// ``HTTPLimits/requestBodyWindowSize``.
        case requestBodyWindowSize
        /// ``HTTPLimits/keepAliveBufferCapacity``.
        case keepAliveBufferCapacity
        /// ``HTTPLimits/headerReadTimeout``.
        case headerReadTimeout
        /// ``HTTPLimits/idleTimeout``.
        case idleTimeout
        /// ``HTTPLimits/keepAliveTimeout``.
        case keepAliveTimeout
        /// ``HTTPLimits/streamResetInterval``.
        case streamResetInterval
        /// ``HTTPLimits/maxConnectionsPerClient``.
        case maxConnectionsPerClient
        /// ``HTTPLimits/maxConnections``.
        case maxConnections
        /// ``HTTPLimits/acceptResumeRatio``.
        case acceptResumeRatio
    }
}
