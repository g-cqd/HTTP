//
//  HTTPLimitsDraft.swift
//  HTTPCore
//
//  The mutable, not-yet-validated face of `HTTPLimits` (2026-07-31 audit, CR-F15), and the two
//  initializers built on it: the clamping one every entry point funnels through, and the throwing one
//  for a caller who would rather hear about a bad value than have it repaired.
//
//  A separate type rather than `var` properties on `HTTPLimits` itself. Mutability *inside* a
//  transaction is exactly what a builder is for; mutability afterwards is what made the invariants
//  decorative, because the last write always won and no write was checked.
//

extension HTTPLimits {
    /// A mutable set of limits that has not been validated yet.
    ///
    /// Every property mirrors the ``HTTPLimits`` property of the same name — see there for what each
    /// bounds, the attack it mitigates, and the range it is held to. Nothing here is checked; a draft
    /// becomes a set of limits only by passing through ``HTTPLimits/init(_:)``, which clamps, or
    /// ``HTTPLimits/init(validating:)``, which refuses.
    public struct Draft: Sendable, Equatable {
        /// Mirrors ``HTTPLimits/maxRequestLineLength``.
        public var maxRequestLineLength: Int
        /// Mirrors ``HTTPLimits/maxFieldSize``.
        public var maxFieldSize: Int
        /// Mirrors ``HTTPLimits/maxHeaderListSize``.
        public var maxHeaderListSize: Int
        /// Mirrors ``HTTPLimits/maxFieldCount``.
        public var maxFieldCount: Int
        /// Mirrors ``HTTPLimits/maxBodySize``.
        public var maxBodySize: Int
        /// Mirrors ``HTTPLimits/maxWebSocketMessageSize``.
        public var maxWebSocketMessageSize: Int?
        /// Mirrors ``HTTPLimits/maxDecompressedBodySize``.
        public var maxDecompressedBodySize: Int
        /// Mirrors ``HTTPLimits/maxDecompressionRatio``.
        public var maxDecompressionRatio: Int
        /// Mirrors ``HTTPLimits/maxDecompressionLayers``.
        public var maxDecompressionLayers: Int
        /// Mirrors ``HTTPLimits/maxConcurrentStreams``.
        public var maxConcurrentStreams: Int
        /// Mirrors ``HTTPLimits/maxFrameSize``.
        public var maxFrameSize: Int
        /// Mirrors ``HTTPLimits/headerTableSize``.
        public var headerTableSize: Int
        /// Mirrors ``HTTPLimits/maxContinuationFrames``.
        public var maxContinuationFrames: Int
        /// Mirrors ``HTTPLimits/maxStreamResetsPerInterval``.
        public var maxStreamResetsPerInterval: Int
        /// Mirrors ``HTTPLimits/maxControlFramesPerInterval``.
        public var maxControlFramesPerInterval: Int
        /// Mirrors ``HTTPLimits/maxQueuedInboundBytes``.
        public var maxQueuedInboundBytes: Int
        /// Mirrors ``HTTPLimits/maxQueuedInboundChunks``.
        public var maxQueuedInboundChunks: Int
        /// Mirrors ``HTTPLimits/maxQueuedBroadcasts``.
        public var maxQueuedBroadcasts: Int
        /// Mirrors ``HTTPLimits/streamReceiveWindow``.
        public var streamReceiveWindow: Int
        /// Mirrors ``HTTPLimits/connectionReceiveWindow``.
        public var connectionReceiveWindow: Int
        /// Mirrors ``HTTPLimits/bodyConsumptionTimeout``.
        public var bodyConsumptionTimeout: Duration
        /// Mirrors ``HTTPLimits/requestBodyWindowSize``.
        public var requestBodyWindowSize: Int
        /// Mirrors ``HTTPLimits/keepAliveBufferCapacity``.
        public var keepAliveBufferCapacity: Int
        /// Mirrors ``HTTPLimits/headerReadTimeout``.
        public var headerReadTimeout: Duration
        /// Mirrors ``HTTPLimits/idleTimeout``.
        public var idleTimeout: Duration
        /// Mirrors ``HTTPLimits/keepAliveTimeout``.
        public var keepAliveTimeout: Duration
        /// Mirrors ``HTTPLimits/streamResetInterval``.
        public var streamResetInterval: Duration
        /// Mirrors ``HTTPLimits/maxConnectionsPerClient``.
        public var maxConnectionsPerClient: Int
        /// Mirrors ``HTTPLimits/maxConnections``.
        public var maxConnections: Int
        /// Mirrors ``HTTPLimits/acceptResumeRatio``.
        public var acceptResumeRatio: Double

        /// Creates a draft holding the current values of `limits`.
        public init(_ limits: HTTPLimits = .default) {
            maxRequestLineLength = limits.maxRequestLineLength
            maxFieldSize = limits.maxFieldSize
            maxHeaderListSize = limits.maxHeaderListSize
            maxFieldCount = limits.maxFieldCount
            maxBodySize = limits.maxBodySize
            maxWebSocketMessageSize = limits.maxWebSocketMessageSize
            maxDecompressedBodySize = limits.maxDecompressedBodySize
            maxDecompressionRatio = limits.maxDecompressionRatio
            maxDecompressionLayers = limits.maxDecompressionLayers
            maxConcurrentStreams = limits.maxConcurrentStreams
            maxFrameSize = limits.maxFrameSize
            headerTableSize = limits.headerTableSize
            maxContinuationFrames = limits.maxContinuationFrames
            maxStreamResetsPerInterval = limits.maxStreamResetsPerInterval
            maxControlFramesPerInterval = limits.maxControlFramesPerInterval
            maxQueuedInboundBytes = limits.maxQueuedInboundBytes
            maxQueuedInboundChunks = limits.maxQueuedInboundChunks
            maxQueuedBroadcasts = limits.maxQueuedBroadcasts
            streamReceiveWindow = limits.streamReceiveWindow
            connectionReceiveWindow = limits.connectionReceiveWindow
            bodyConsumptionTimeout = limits.bodyConsumptionTimeout
            requestBodyWindowSize = limits.requestBodyWindowSize
            keepAliveBufferCapacity = limits.keepAliveBufferCapacity
            headerReadTimeout = limits.headerReadTimeout
            idleTimeout = limits.idleTimeout
            keepAliveTimeout = limits.keepAliveTimeout
            streamResetInterval = limits.streamResetInterval
            maxConnectionsPerClient = limits.maxConnectionsPerClient
            maxConnections = limits.maxConnections
            acceptResumeRatio = limits.acceptResumeRatio
        }

        /// Creates a draft from explicit values.
        init(
            maxRequestLineLength: Int,
            maxFieldSize: Int,
            maxHeaderListSize: Int,
            maxFieldCount: Int,
            maxBodySize: Int,
            maxWebSocketMessageSize: Int?,
            maxDecompressedBodySize: Int,
            maxDecompressionRatio: Int,
            maxDecompressionLayers: Int,
            maxConcurrentStreams: Int,
            maxFrameSize: Int,
            headerTableSize: Int,
            maxContinuationFrames: Int,
            maxStreamResetsPerInterval: Int,
            maxControlFramesPerInterval: Int,
            maxQueuedInboundBytes: Int,
            maxQueuedInboundChunks: Int,
            maxQueuedBroadcasts: Int,
            streamReceiveWindow: Int,
            connectionReceiveWindow: Int,
            bodyConsumptionTimeout: Duration,
            requestBodyWindowSize: Int,
            keepAliveBufferCapacity: Int,
            headerReadTimeout: Duration,
            idleTimeout: Duration,
            keepAliveTimeout: Duration,
            streamResetInterval: Duration,
            maxConnectionsPerClient: Int,
            maxConnections: Int,
            acceptResumeRatio: Double
        ) {
            self.maxRequestLineLength = maxRequestLineLength
            self.maxFieldSize = maxFieldSize
            self.maxHeaderListSize = maxHeaderListSize
            self.maxFieldCount = maxFieldCount
            self.maxBodySize = maxBodySize
            self.maxWebSocketMessageSize = maxWebSocketMessageSize
            self.maxDecompressedBodySize = maxDecompressedBodySize
            self.maxDecompressionRatio = maxDecompressionRatio
            self.maxDecompressionLayers = maxDecompressionLayers
            self.maxConcurrentStreams = maxConcurrentStreams
            self.maxFrameSize = maxFrameSize
            self.headerTableSize = headerTableSize
            self.maxContinuationFrames = maxContinuationFrames
            self.maxStreamResetsPerInterval = maxStreamResetsPerInterval
            self.maxControlFramesPerInterval = maxControlFramesPerInterval
            self.maxQueuedInboundBytes = maxQueuedInboundBytes
            self.maxQueuedInboundChunks = maxQueuedInboundChunks
            self.maxQueuedBroadcasts = maxQueuedBroadcasts
            self.streamReceiveWindow = streamReceiveWindow
            self.connectionReceiveWindow = connectionReceiveWindow
            self.bodyConsumptionTimeout = bodyConsumptionTimeout
            self.requestBodyWindowSize = requestBodyWindowSize
            self.keepAliveBufferCapacity = keepAliveBufferCapacity
            self.headerReadTimeout = headerReadTimeout
            self.idleTimeout = idleTimeout
            self.keepAliveTimeout = keepAliveTimeout
            self.streamResetInterval = streamResetInterval
            self.maxConnectionsPerClient = maxConnectionsPerClient
            self.maxConnections = maxConnections
            self.acceptResumeRatio = acceptResumeRatio
        }
    }

    /// Creates a set of limits from `draft`, clamping every value into its documented range.
    ///
    /// The single clamp site. Every other entry point — the memberwise initializer, ``with(_:)``, the
    /// presets — reaches the stored properties through here, so there is exactly one definition of
    /// what a legal set of limits is and no way to construct one that disagrees with it.
    ///
    /// Complexity 1 by construction: every line is one table lookup and one assignment, so a new limit
    /// costs a row in the table and never a branch here.
    public init(_ draft: Draft) {
        maxRequestLineLength = Bounds.requestLine.clamping(draft.maxRequestLineLength)
        maxFieldSize = Bounds.fieldSize.clamping(draft.maxFieldSize)
        maxHeaderListSize = Bounds.headerList.clamping(draft.maxHeaderListSize)
        maxFieldCount = Bounds.fieldCount.clamping(draft.maxFieldCount)
        maxBodySize = Bounds.bodySize.clamping(draft.maxBodySize)
        // Clamped through `map`: `nil` is legal and means "follow maxBodySize", already clamped above.
        let webSocket = draft.maxWebSocketMessageSize
        maxWebSocketMessageSize = webSocket.map(Bounds.webSocketMessage.clamping)
        maxDecompressionRatio = Bounds.decompressionRatio.clamping(draft.maxDecompressionRatio)
        maxDecompressionLayers = Bounds.decompressionLayers.clamping(draft.maxDecompressionLayers)
        maxConcurrentStreams = Bounds.streams.clamping(draft.maxConcurrentStreams)
        maxFrameSize = Bounds.frame.clamping(draft.maxFrameSize)
        headerTableSize = Bounds.headerTable.clamping(draft.headerTableSize)
        maxContinuationFrames = Bounds.continuations.clamping(draft.maxContinuationFrames)
        maxStreamResetsPerInterval = Bounds.resets.clamping(draft.maxStreamResetsPerInterval)
        maxControlFramesPerInterval = Bounds.control.clamping(draft.maxControlFramesPerInterval)
        maxQueuedInboundBytes = Bounds.queuedBytes.clamping(draft.maxQueuedInboundBytes)
        maxQueuedInboundChunks = Bounds.queuedChunks.clamping(draft.maxQueuedInboundChunks)
        maxQueuedBroadcasts = Bounds.queuedBroadcasts.clamping(draft.maxQueuedBroadcasts)
        connectionReceiveWindow = Bounds.window.clamping(draft.connectionReceiveWindow)
        bodyConsumptionTimeout = Bounds.positive(draft.bodyConsumptionTimeout)
        requestBodyWindowSize = Bounds.bodyWindow.clamping(draft.requestBodyWindowSize)
        keepAliveBufferCapacity = Bounds.keepAliveBuffer.clamping(draft.keepAliveBufferCapacity)
        headerReadTimeout = Bounds.positive(draft.headerReadTimeout)
        idleTimeout = Bounds.positive(draft.idleTimeout)
        keepAliveTimeout = Bounds.positive(draft.keepAliveTimeout)
        streamResetInterval = Bounds.positive(draft.streamResetInterval)
        maxConnections = Bounds.connections.clamping(draft.maxConnections)
        acceptResumeRatio = Bounds.clamping(draft.acceptResumeRatio)
        // The three cross-field invariants, each repaired in the direction that keeps what the caller
        // asked for. A decompressed cap below the raw cap would refuse bodies that shrank on the way
        // through; a per-client ceiling above the global one cannot bind; a stream window above the
        // connection window is unreachable because the connection window is debited first.
        maxDecompressedBodySize = max(
            Bounds.decompressedBody.clamping(draft.maxDecompressedBodySize),
            maxBodySize
        )
        maxConnectionsPerClient = min(
            Bounds.connections.clamping(draft.maxConnectionsPerClient),
            maxConnections
        )
        streamReceiveWindow = min(
            Bounds.window.clamping(draft.streamReceiveWindow),
            connectionReceiveWindow
        )
    }

    /// Creates a set of limits from `draft`, throwing on the first value that is out of range or
    /// incoherent.
    ///
    /// The entry point for configuration that arrives from outside the program — a file, a flag, an
    /// environment variable — where a silent repair hides the bug instead of fixing it. Nothing is
    /// clamped: a draft either is a legal set of limits or is refused with the name of the limit that
    /// made it illegal.
    public init(validating draft: Draft) throws(HTTPLimitsError) {
        try draft.validate()
        self.init(draft)
    }
}
