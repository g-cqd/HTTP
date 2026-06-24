//
//  HTTPLimits.swift
//  HTTPCore
//
//  Defense-in-depth resource limits. Engines enforce these and fail closed on breach (the two
//  inbound-decompression bounds are reserved until that feature lands — see their notes).
//  Defaults are the reconciled safe values from the project's security analysis (RFCs + CVEs).
//

/// Configurable, safe-by-default resource limits enforced by every protocol engine.
///
/// These bound the work an adversary can force the server to do, so that malformed or hostile
/// traffic fails closed (with the correct protocol error) instead of exhausting memory or CPU. Each
/// limit is annotated with the attack it mitigates.
public struct HTTPLimits: Sendable, Equatable {
    // MARK: Message size limits

    /// Maximum request-line / `:path` length before responding `414` (RFC 9112 §3; buffer abuse).
    public var maxRequestLineLength: Int

    /// Maximum size of a single header field (name + value) before responding `431` (header abuse).
    public var maxFieldSize: Int

    /// Maximum total decoded header-list size (resource exhaustion; h2 `SETTINGS_MAX_HEADER_LIST_SIZE`).
    public var maxHeaderListSize: Int

    /// Maximum number of header fields per message (exhaustion; HTTP/2 Cookie-splitting).
    public var maxFieldCount: Int

    /// Maximum request body size before responding `413` (RFC 9110 §15.5.14).
    public var maxBodySize: Int

    /// Maximum size of an inbound decompressed body (gzip/brotli decompression bombs; CWE-409).
    ///
    /// Reserved, **not yet enforced**: the server performs only response-side compression today, so no
    /// request body is decompressed. This bound activates when inbound `Content-Encoding` decoding is
    /// added.
    public var maxDecompressedBodySize: Int

    /// Maximum decompressed-to-compressed size ratio for an inbound body (decompression bombs).
    ///
    /// Reserved alongside ``maxDecompressedBodySize`` — **not yet enforced** (no inbound decompression).
    public var maxDecompressionRatio: Int

    // MARK: HTTP/2 & HTTP/3 limits

    /// Advertised `SETTINGS_MAX_CONCURRENT_STREAMS` (exhaustion; RFC 9113 §5.1.2).
    public var maxConcurrentStreams: Int

    /// Maximum accepted frame payload size (RFC 9113 §4.2 floor is 16,384).
    public var maxFrameSize: Int

    /// HPACK / QPACK dynamic table capacity in bytes (decompression bomb; RFC 7541 §4.2).
    public var headerTableSize: Int

    /// Maximum `CONTINUATION` frames per header block (CONTINUATION flood, CVE-2024-27316).
    public var maxContinuationFrames: Int

    /// Maximum `RST_STREAM` churn per ``streamResetInterval`` before `GOAWAY` (Rapid Reset,
    /// CVE-2023-44487).
    public var maxStreamResetsPerInterval: Int

    // MARK: Timeouts (Slowloris / slow-read defenses)

    /// Maximum time to receive a complete header section (Slowloris; → `408`).
    public var headerReadTimeout: Duration

    /// Maximum idle time on a connection before it is closed.
    public var idleTimeout: Duration

    /// Maximum idle time on a persistent HTTP/1.1 connection between requests.
    public var keepAliveTimeout: Duration

    /// The rolling window over which ``maxStreamResetsPerInterval`` is measured.
    public var streamResetInterval: Duration

    // MARK: Connection limits

    /// Maximum simultaneous connections from a single client address (→ `429`).
    public var maxConnectionsPerClient: Int

    /// Maximum simultaneous connections across all clients — a global resource ceiling against FD /
    /// task exhaustion (audit T-F2).
    ///
    /// Connections beyond it are closed immediately. Tune up for high-concurrency deployments (and
    /// raise the process file-descriptor limit to match).
    public var maxConnections: Int

    /// Creates a set of limits; every parameter defaults to its documented safe value.
    public init(
        maxRequestLineLength: Int = 8 * 1_024,
        maxFieldSize: Int = 16 * 1_024,
        maxHeaderListSize: Int = 64 * 1_024,
        maxFieldCount: Int = 100,
        maxBodySize: Int = 1 << 30,  // 1 GiB
        maxDecompressedBodySize: Int = 1 << 30,
        maxDecompressionRatio: Int = 10,
        maxConcurrentStreams: Int = 1_048_576,
        maxFrameSize: Int = 16 * 1_024,
        headerTableSize: Int = 4 * 1_024,
        maxContinuationFrames: Int = 100,
        maxStreamResetsPerInterval: Int = 100,
        headerReadTimeout: Duration = .seconds(10),
        idleTimeout: Duration = .seconds(60),
        keepAliveTimeout: Duration = .seconds(15),
        streamResetInterval: Duration = .seconds(1),
        maxConnectionsPerClient: Int = 1_048_576,
        maxConnections: Int = 1_048_576
    ) {
        self.maxRequestLineLength = maxRequestLineLength
        self.maxFieldSize = maxFieldSize
        self.maxHeaderListSize = maxHeaderListSize
        self.maxFieldCount = maxFieldCount
        self.maxBodySize = maxBodySize
        self.maxDecompressedBodySize = maxDecompressedBodySize
        self.maxDecompressionRatio = maxDecompressionRatio
        self.maxConcurrentStreams = maxConcurrentStreams
        self.maxFrameSize = maxFrameSize
        self.headerTableSize = headerTableSize
        self.maxContinuationFrames = maxContinuationFrames
        self.maxStreamResetsPerInterval = maxStreamResetsPerInterval
        self.headerReadTimeout = headerReadTimeout
        self.idleTimeout = idleTimeout
        self.keepAliveTimeout = keepAliveTimeout
        self.streamResetInterval = streamResetInterval
        self.maxConnectionsPerClient = maxConnectionsPerClient
        self.maxConnections = maxConnections
    }

    /// The default, safe-by-default limits.
    public static let `default` = Self()
}
