//
//  HTTPLimits.swift
//  HTTPCore
//
//  Defense-in-depth resource limits. Engines enforce these and fail closed on breach (the two
//  inbound-decompression bounds are reserved until that feature lands — see their notes).
//  Defaults are the reconciled safe values from the project's security analysis (RFCs + CVEs).
//

/// Configurable resource limits enforced by every protocol engine.
///
/// The size, count, and timeout guards bound the work malformed or hostile traffic can force, so it
/// fails closed (with the correct protocol error) instead of exhausting memory or CPU — each is
/// annotated with the attack it mitigates, and a normal request stays far below every threshold.
///
/// The connection *ceilings* (``maxConnectionsPerClient``, ``maxConnections``) and the per-connection
/// ``maxConcurrentStreams`` default to **secure, non-throttling** values: bounding the per-connection
/// stream table and the per-/global-connection count costs **zero** requests-per-second (throughput is
/// across many connections, not within one) while denying a single peer the memory / file-descriptor
/// amplification of unbounded streams or sockets. Use ``highThroughput`` to raise the connection
/// ceilings for a trusted or benchmark environment, or ``hardened`` for a tighter public posture.
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

    /// Advertised + enforced `SETTINGS_MAX_CONCURRENT_STREAMS` — the per-connection open-stream bound.
    ///
    /// A stream-state exhaustion DoS guard (RFC 9113 §5.1.2, whose recommended floor is ≥100); default
    /// 128. Unlike the connection ceilings it is *not* permissive: one connection opening unbounded
    /// concurrent streams would exhaust memory, so it stays bounded even in a trusted environment.
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

    /// Maximum cheap/abusive control-plane frames per ``streamResetInterval`` before `GOAWAY`.
    ///
    /// Counts the frames that are cheap to send but do no useful work — PING / SETTINGS (and their
    /// ACKs), PRIORITY, zero-length non-final DATA, and WINDOW_UPDATE on a closed stream — so a flood
    /// of them is a CPU-exhaustion DoS (CVE-2019-9513 PRIORITY, CVE-2019-9518 empty DATA). A completed
    /// request drains the budget and it decays each ``streamResetInterval``; kept separate from
    /// ``maxStreamResetsPerInterval`` so resets and control frames are bounded independently.
    public var maxControlFramesPerInterval: Int

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

    /// Creates a set of limits.
    ///
    /// Size/count guards and timeouts default to conservative values; the connection ceilings default
    /// to secure, non-throttling values (``maxConnectionsPerClient`` 1024, ``maxConnections`` 65_536)
    /// and ``maxConcurrentStreams`` stays bounded at 128. See ``highThroughput`` / ``hardened``.
    public init(
        maxRequestLineLength: Int = 8 * 1_024,
        maxFieldSize: Int = 16 * 1_024,
        maxHeaderListSize: Int = 64 * 1_024,
        maxFieldCount: Int = 100,
        maxBodySize: Int = 1 << 30,  // 1 GiB
        maxDecompressedBodySize: Int = 1 << 30,
        maxDecompressionRatio: Int = 10,
        maxConcurrentStreams: Int = 128,
        maxFrameSize: Int = 16 * 1_024,
        headerTableSize: Int = 4 * 1_024,
        maxContinuationFrames: Int = 100,
        maxStreamResetsPerInterval: Int = 100,
        maxControlFramesPerInterval: Int = 1_000,
        headerReadTimeout: Duration = .seconds(10),
        idleTimeout: Duration = .seconds(60),
        keepAliveTimeout: Duration = .seconds(15),
        streamResetInterval: Duration = .seconds(1),
        maxConnectionsPerClient: Int = 1_024,
        maxConnections: Int = 65_536
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
        self.maxControlFramesPerInterval = maxControlFramesPerInterval
        self.headerReadTimeout = headerReadTimeout
        self.idleTimeout = idleTimeout
        self.keepAliveTimeout = keepAliveTimeout
        self.streamResetInterval = streamResetInterval
        self.maxConnectionsPerClient = maxConnectionsPerClient
        self.maxConnections = maxConnections
    }

    /// The default limits — safe out of the box: conservative size/count/timeout guards and secure,
    /// non-throttling connection ceilings with a bounded 128-stream per-connection cap.
    public static let `default` = Self()

    /// A high-throughput / trusted-environment preset that raises the connection ceilings.
    ///
    /// The ceilings go far above any legitimate need so they never throttle a benchmark or a trusted
    /// internal peer. Use ONLY where the peer set is trusted — it disables the connection-exhaustion
    /// bounds that ``default`` provides. ``maxConcurrentStreams`` stays bounded (a memory bound, never
    /// a throughput one).
    public static let highThroughput = Self(
        maxConnectionsPerClient: 1_048_576,
        maxConnections: 1_048_576
    )

    /// Hardened preset for hostile / public-facing deployments: tighter sizes, counts, timeouts, and
    /// ceilings than ``default`` — trading some legitimate-client headroom for a smaller attack surface.
    public static let hardened = Self(
        maxRequestLineLength: 4 * 1_024,
        maxFieldSize: 8 * 1_024,
        maxHeaderListSize: 32 * 1_024,
        maxFieldCount: 64,
        maxBodySize: 16 << 20,
        maxConcurrentStreams: 100,
        maxContinuationFrames: 32,
        maxStreamResetsPerInterval: 50,
        maxControlFramesPerInterval: 200,
        headerReadTimeout: .seconds(5),
        idleTimeout: .seconds(30),
        keepAliveTimeout: .seconds(5),
        maxConnectionsPerClient: 64,
        maxConnections: 16_384
    )
}
