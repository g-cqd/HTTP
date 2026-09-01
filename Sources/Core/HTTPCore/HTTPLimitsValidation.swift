//
//  HTTPLimitsValidation.swift
//  HTTPCore
//
//  The refusing half of `HTTPLimits` validation (2026-07-31 audit, CR-F15). It reads the same
//  `HTTPLimits.Bounds` table the clamping initializer does, so the two cannot drift: whatever a clamp
//  would silently repair is exactly what this refuses, by construction rather than by review.
//

extension HTTPLimits.Draft {
    /// Throws unless every limit is inside its documented range and coherent with the others.
    ///
    /// One `try` per invariant and no branches, so the cyclomatic complexity is 1 no matter how many
    /// limits the type grows: the branch lives once, in the helper each line calls.
    func validate() throws(HTTPLimitsError) {
        try check(maxRequestLineLength, .maxRequestLineLength, in: Bounds.requestLine)
        try check(maxFieldSize, .maxFieldSize, in: Bounds.fieldSize)
        try check(maxHeaderListSize, .maxHeaderListSize, in: Bounds.headerList)
        try check(maxFieldCount, .maxFieldCount, in: Bounds.fieldCount)
        try check(maxBodySize, .maxBodySize, in: Bounds.bodySize)
        try checkWebSocketMessageSize()
        try check(maxDecompressedBodySize, .maxDecompressedBodySize, in: Bounds.decompressedBody)
        try check(maxDecompressionRatio, .maxDecompressionRatio, in: Bounds.decompressionRatio)
        try check(maxDecompressionLayers, .maxDecompressionLayers, in: Bounds.decompressionLayers)
        try check(maxConcurrentStreams, .maxConcurrentStreams, in: Bounds.streams)
        try check(maxFrameSize, .maxFrameSize, in: Bounds.frame)
        try check(headerTableSize, .headerTableSize, in: Bounds.headerTable)
        try check(maxContinuationFrames, .maxContinuationFrames, in: Bounds.continuations)
        try check(maxStreamResetsPerInterval, .maxStreamResetsPerInterval, in: Bounds.resets)
        try check(maxControlFramesPerInterval, .maxControlFramesPerInterval, in: Bounds.control)
        try check(maxQueuedInboundBytes, .maxQueuedInboundBytes, in: Bounds.queuedBytes)
        try check(maxQueuedInboundChunks, .maxQueuedInboundChunks, in: Bounds.queuedChunks)
        try check(maxQueuedBroadcasts, .maxQueuedBroadcasts, in: Bounds.queuedBroadcasts)
        try check(streamReceiveWindow, .streamReceiveWindow, in: Bounds.window)
        try check(connectionReceiveWindow, .connectionReceiveWindow, in: Bounds.window)
        try check(requestBodyWindowSize, .requestBodyWindowSize, in: Bounds.bodyWindow)
        try check(keepAliveBufferCapacity, .keepAliveBufferCapacity, in: Bounds.keepAliveBuffer)
        try check(maxConnectionsPerClient, .maxConnectionsPerClient, in: Bounds.connections)
        try check(maxConnections, .maxConnections, in: Bounds.connections)
        try checkPositive(bodyConsumptionTimeout, .bodyConsumptionTimeout)
        try checkPositive(headerReadTimeout, .headerReadTimeout)
        try checkPositive(idleTimeout, .idleTimeout)
        try checkPositive(keepAliveTimeout, .keepAliveTimeout)
        try checkPositive(streamResetInterval, .streamResetInterval)
        try checkRatio()
        try checkCoherence()
    }

    /// The three invariants no single field's range can express.
    ///
    /// Each side is legal on its own; only the pair is wrong, which is precisely why they were never
    /// caught before — a per-field check has nothing to compare against.
    private func checkCoherence() throws(HTTPLimitsError) {
        try check(
            maxConnectionsPerClient,
            .maxConnectionsPerClient,
            atMost: maxConnections,
            .maxConnections
        )
        try check(
            streamReceiveWindow,
            .streamReceiveWindow,
            atMost: connectionReceiveWindow,
            .connectionReceiveWindow
        )
        try check(
            maxBodySize,
            .maxBodySize,
            atMost: maxDecompressedBodySize,
            .maxDecompressedBodySize
        )
    }

    /// Throws unless `value` is inside `range`.
    private func check(
        _ value: Int,
        _ limit: HTTPLimitsError.Limit,
        in range: ClosedRange<Int>
    ) throws(HTTPLimitsError) {
        guard range.contains(value) else {
            throw .outOfRange(limit: limit, allowed: "\(range.lowerBound) ... \(range.upperBound)")
        }
    }

    /// Throws unless `value` is at most `ceiling`.
    private func check(
        _ value: Int,
        _ limit: HTTPLimitsError.Limit,
        atMost ceiling: Int,
        _ ceilingLimit: HTTPLimitsError.Limit
    ) throws(HTTPLimitsError) {
        guard value <= ceiling else {
            throw .incoherent(limit: limit, mustNotExceed: ceilingLimit)
        }
    }

    /// Throws unless `duration` is strictly positive.
    private func checkPositive(
        _ duration: Duration,
        _ limit: HTTPLimitsError.Limit
    ) throws(HTTPLimitsError) {
        guard duration >= Bounds.minimumDuration else {
            throw .outOfRange(limit: limit, allowed: "strictly positive")
        }
    }

    /// Throws unless the WebSocket message cap, when set, is inside its range.
    ///
    /// `nil` is legal and means "follow `maxBodySize`", which was already validated.
    private func checkWebSocketMessageSize() throws(HTTPLimitsError) {
        guard let size = maxWebSocketMessageSize else {
            return
        }
        try check(size, .maxWebSocketMessageSize, in: Bounds.webSocketMessage)
    }

    /// Throws unless the accept-resume ratio is a finite fraction.
    ///
    /// `isFinite` and not just a range test: NaN is unordered, so `Bounds.ratio.contains(.nan)` is
    /// false for the wrong reason and `±.infinity` would otherwise be reported as merely out of range.
    /// Downstream, a non-finite ratio reaches an `Int` conversion that traps (IEEE 754-2019 §7.2).
    private func checkRatio() throws(HTTPLimitsError) {
        guard acceptResumeRatio.isFinite, Bounds.ratio.contains(acceptResumeRatio) else {
            throw .outOfRange(limit: .acceptResumeRatio, allowed: "a finite 0.0 ... 1.0")
        }
    }

    /// The shared range table, spelled once.
    private typealias Bounds = HTTPLimits.Bounds
}
