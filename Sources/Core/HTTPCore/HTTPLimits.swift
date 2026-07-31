//
//  HTTPLimits.swift
//  HTTPCore
//
//  Defense-in-depth resource limits. Engines enforce these and fail closed on breach (the three
//  inbound-decompression bounds are enforced by the opt-in `DecompressionMiddleware` — see their
//  notes). Defaults are the reconciled safe values from the project's security analysis (RFCs + CVEs).
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
    ///
    /// The global bound; a route's `bodyLimited(to:)` cap **replaces** it for requests matched to that
    /// route (Phase 1.2) — it may tighten or raise it.
    public var maxBodySize: Int

    /// Maximum reassembled WebSocket message size in octets (RFC 6455 §5.4 — fragments buffer until
    /// the final frame), or `nil` to follow ``maxBodySize``.
    ///
    /// A dedicated knob because a WebSocket message cap and an HTTP request-body cap guard different
    /// traffic: raising one should not silently raise the other (message-reassembly memory
    /// exhaustion). `nil` (the default) preserves the historical coupling to ``maxBodySize``.
    public var maxWebSocketMessageSize: Int?

    /// The enforced WebSocket message cap: ``maxWebSocketMessageSize`` when set, else ``maxBodySize``.
    public var effectiveWebSocketMessageSize: Int { maxWebSocketMessageSize ?? maxBodySize }

    /// Maximum size of an inbound decompressed body (gzip/brotli decompression bombs; CWE-409).
    ///
    /// Enforced by the opt-in `DecompressionMiddleware`, which is the only thing in the server that
    /// decodes an inbound `Content-Encoding`; a build without it never decompresses a request body.
    public var maxDecompressedBodySize: Int

    /// Maximum decompressed-to-compressed size ratio for an inbound body (decompression bombs).
    ///
    /// Charged against the size the peer actually sent, so it bounds total amplification even when
    /// several codings are stacked. Enforced alongside ``maxDecompressedBodySize``.
    public var maxDecompressionRatio: Int

    /// Maximum number of stacked inbound content codings (RFC 9110 §8.4.1).
    ///
    /// `Content-Encoding` is an ordered list and each entry costs a full decode pass, so an
    /// arbitrarily long list is CPU amplification from a single header (CWE-409). Real traffic uses
    /// one coding; the default of 2 leaves room for the legal `gzip, br` shape and refuses deeper
    /// nesting with `415 Unsupported Media Type`.
    public var maxDecompressionLayers: Int

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

    // MARK: Transport→application handoff bounds (backpressure)

    /// Unconsumed octets a transport intake channel holds before the reader task parks.
    ///
    /// The reader parking is the backpressure: it stops calling `receive`, so the kernel buffer fills
    /// and the peer's TCP window closes. Bounds the HTTP/1.1 WebSocket intake and the HTTP/2 raw
    /// mailbox, which were previously lossy and unbounded respectively (2026-07-31 audit, F1/F3).
    public var maxQueuedInboundBytes: Int

    /// Unconsumed chunks a transport intake channel holds before the reader task parks.
    ///
    /// A second, independent bound on the *ticket* count a merged mailbox can accumulate — a count of
    /// chunks does not bound memory, and a byte watermark alone does not bound ticket cardinality when
    /// a peer dribbles tiny frames.
    public var maxQueuedInboundChunks: Int

    /// Undelivered hub broadcasts a single WebSocket connection queues before the oldest is dropped.
    ///
    /// Unlike transport octets, broadcasts may be dropped — but never silently: the drop is counted
    /// and the connection is closed with `1008` (RFC 6455 §7.4.1) rather than pretending it delivered.
    public var maxQueuedBroadcasts: Int

    // MARK: HTTP/2 consumption-gated receive windows (backpressure)

    /// The advertised `SETTINGS_INITIAL_WINDOW_SIZE` — unconsumed octets one HTTP/2 stream may hold.
    ///
    /// On a consumption-gated stream (a streaming route or an RFC 8441 tunnel) the window is debited as
    /// the peer sends and credited back only as the *handler* takes each chunk, so this **is** the
    /// per-stream memory watermark — no parallel accounting (RFC 9113 §6.9, ADR 0006).
    public var streamReceiveWindow: Int

    /// The connection-level receive window — unconsumed octets one HTTP/2 connection may hold, across
    /// every stream.
    ///
    /// The hard bound consumption gating buys: at most this many un-taken application octets exist per
    /// connection regardless of stream count, route body limit, or handler behavior. RFC 9113 §6.9.2
    /// fixes the initial value at 65,535 and SETTINGS cannot change it, so the engine raises it with a
    /// stream-0 `WINDOW_UPDATE` in its preface.
    ///
    /// Throughput cost: a window of `W` at round-trip time `T` ceilings one connection's *upload* at
    /// `W / T` — 1 MiB at 50 ms is ≈ 20 MB/s. ``highThroughput`` raises it 8×.
    public var connectionReceiveWindow: Int

    /// How long a gated HTTP/2 stream may hold receive credit without the handler consuming any of it.
    ///
    /// Consumption gating means one non-consuming handler holds the *shared* connection window and so
    /// stalls every sibling stream — that is HTTP/2's semantics, not a bug, but it must not be
    /// unbounded. A stream that makes no consumption progress across two sweeps of half this duration
    /// is reset with `ENHANCE_YOUR_CALM` (RFC 9113 §7) and its siblings continue.
    public var bodyConsumptionTimeout: Duration

    // MARK: HTTP/1.1 streamed request bodies (backpressure + reclaim)

    /// The fixed receive window a *streamed* HTTP/1.1 chunked request body is framed inside.
    ///
    /// HTTP/1.1 has no flow control of its own, so the backpressure is the reader parking: the body
    /// producer suspends until the handler takes each decoded chunk, stops calling `receive`, and the
    /// peer's TCP window closes. This bounds what one connection holds while that happens — the wire
    /// octets not yet framed. A Content-Length body needs no window at all (its remaining length *is*
    /// the bound), so this applies only to the chunked coding (RFC 9112 §7.1).
    ///
    /// Floored by ``effectiveRequestBodyWindow`` so a maximal chunk-size / chunk-extension / trailer
    /// line always fits: a window smaller than one line could neither frame it nor refuse it.
    public var requestBodyWindowSize: Int

    /// The largest read-buffer capacity a persistent HTTP/1.1 connection keeps between requests.
    ///
    /// A *buffered* request body is accumulated in that buffer, so one large upload leaves an
    /// upload-sized allocation behind — and `removeAll(keepingCapacity:)` would then hand that peak to
    /// every later request on the connection, for as long as the peer keeps it open. Past this ceiling
    /// the storage is released instead and grows back geometrically, as it did on the connection's
    /// first request: a handful of allocations on the rare large request, against unbounded
    /// per-connection retention for the common small one (CWE-401-shaped).
    public var keepAliveBufferCapacity: Int

    /// The enforced streaming chunked receive window: ``requestBodyWindowSize``, floored so a maximal
    /// framing line plus a full read always fits.
    ///
    /// The floor is what makes the window deadlock-free. `readLine` refuses a chunk-size / extension /
    /// trailer line once the unframed octets pass ``maxFieldSize``, so with strictly more room than
    /// that the decoder always either consumes or fails closed — it can never answer "need more" to a
    /// window that has no more to give (RFC 9112 §7.1.1, §7.1.2).
    public var effectiveRequestBodyWindow: Int { max(requestBodyWindowSize, maxFieldSize + 16_384) }

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

    /// The fraction of ``maxConnections`` the live count must fall back to before a saturated accept
    /// source re-arms — hysteresis preventing suspend/resume churn at the ceiling (audit F8).
    ///
    /// Without it a server sitting exactly at ``maxConnections`` would suspend and re-arm its accept
    /// source on every single close — a `kevent`/`epoll_ctl` syscall storm at the worst moment.
    /// Clamped to `0...1`; `1.0` disables the hysteresis (re-arm on the first free slot).
    public var acceptResumeRatio: Double

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
        maxWebSocketMessageSize: Int? = nil,  // follow maxBodySize
        maxDecompressedBodySize: Int = 1 << 30,
        maxDecompressionRatio: Int = 10,
        maxDecompressionLayers: Int = 2,
        maxConcurrentStreams: Int = 128,
        maxFrameSize: Int = 16 * 1_024,
        headerTableSize: Int = 4 * 1_024,
        maxContinuationFrames: Int = 100,
        maxStreamResetsPerInterval: Int = 100,
        maxControlFramesPerInterval: Int = 1_000,
        maxQueuedInboundBytes: Int = 256 * 1_024,
        maxQueuedInboundChunks: Int = 64,
        maxQueuedBroadcasts: Int = 64,
        streamReceiveWindow: Int = 256 * 1_024,
        connectionReceiveWindow: Int = 1 << 20,  // 1 MiB
        bodyConsumptionTimeout: Duration = .seconds(60),
        requestBodyWindowSize: Int = 64 * 1_024,
        keepAliveBufferCapacity: Int = 64 * 1_024,
        headerReadTimeout: Duration = .seconds(10),
        idleTimeout: Duration = .seconds(60),
        keepAliveTimeout: Duration = .seconds(15),
        streamResetInterval: Duration = .seconds(1),
        maxConnectionsPerClient: Int = 1_024,
        maxConnections: Int = 65_536,
        acceptResumeRatio: Double = 0.875
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
        maxQueuedInboundBytes: 1 << 20,
        maxQueuedInboundChunks: 256,
        maxQueuedBroadcasts: 256,
        streamReceiveWindow: 1 << 20,  // 1 MiB
        connectionReceiveWindow: 8 << 20,  // 8 MiB — ≈ 160 MB/s per connection at 50 ms RTT
        requestBodyWindowSize: 256 * 1_024,
        keepAliveBufferCapacity: 256 * 1_024,
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
        maxQueuedInboundBytes: 64 * 1_024,
        maxQueuedInboundChunks: 32,
        maxQueuedBroadcasts: 16,
        streamReceiveWindow: 64 * 1_024,
        connectionReceiveWindow: 256 * 1_024,
        bodyConsumptionTimeout: .seconds(30),
        requestBodyWindowSize: 32 * 1_024,
        keepAliveBufferCapacity: 32 * 1_024,
        headerReadTimeout: .seconds(5),
        idleTimeout: .seconds(30),
        keepAliveTimeout: .seconds(5),
        maxConnectionsPerClient: 64,
        maxConnections: 16_384
    )
}
