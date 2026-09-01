//
//  HTTPLimits.swift
//  HTTPCore
//
//  Defense-in-depth resource limits. Engines enforce these and fail closed on breach (the three
//  inbound-decompression bounds are enforced by the opt-in `DecompressionMiddleware` — see their
//  notes). Defaults are the reconciled safe values from the project's security analysis (RFCs + CVEs).
//
//  Every property is `let` and every value passes through one clamp on the way in (2026-07-31 audit,
//  CR-F15). The legal ranges live in `HTTPLimitsBounds.swift`; `HTTPLimitsDraft.swift` carries the
//  mutable draft that `with { }` and `init(validating:)` are built on.
//

/// Configurable resource limits enforced by every protocol engine.
///
/// The size, count, and timeout guards bound the work malformed or hostile traffic can force, so it
/// fails closed (with the correct protocol error) instead of exhausting memory or CPU — each is
/// annotated with the attack it mitigates, and a normal request stays far below every threshold.
///
/// **The values are immutable and validated.** Every property is `public let`, and the only ways in
/// are the clamping initializer below, the throwing ``init(validating:)``, and ``with(_:)`` — each of
/// which re-establishes every range and cross-field invariant this type documents. That is the whole
/// point: an invariant a type announces and then lets a caller overwrite field by field is a comment,
/// not an invariant, and consumers were compensating for it with defensive clamps of their own.
///
/// The connection *ceilings* (``maxConnectionsPerClient``, ``maxConnections``) and the per-connection
/// ``maxConcurrentStreams`` default to **secure, non-throttling** values: bounding the per-connection
/// stream table and the per-/global-connection count costs **zero** requests-per-second (throughput is
/// across many connections, not within one) while denying a single peer the memory / file-descriptor
/// amplification of unbounded streams or sockets. Use ``highThroughput`` to raise the connection
/// ceilings for a trusted or benchmark environment, or ``hardened`` for a tighter public posture.
///
/// > Important: The conservative size defaults narrow the window on a memory-exhaustion bug; they do
/// > not close it, and they are **not** a substitute for backpressure. What actually bounds what one
/// > connection can make the server hold is the bounded transport→application handoff
/// > (``maxQueuedInboundBytes``, ``maxQueuedInboundChunks``) and the consumption-gated receive windows
/// > (``streamReceiveWindow``, ``connectionReceiveWindow``). A body cap only bounds one request.
public struct HTTPLimits: Sendable, Equatable {
    // MARK: Message size limits

    /// Maximum request-line / `:path` length before responding `414` (RFC 9112 §3; buffer abuse).
    ///
    /// At least 1.
    public let maxRequestLineLength: Int

    /// Maximum size of a single header field (name + value) before responding `431` (header abuse).
    ///
    /// At least 1.
    public let maxFieldSize: Int

    /// Maximum total decoded header-list size (resource exhaustion; h2 `SETTINGS_MAX_HEADER_LIST_SIZE`).
    ///
    /// At least 0.
    public let maxHeaderListSize: Int

    /// Maximum number of header fields per message (exhaustion; HTTP/2 Cookie-splitting).
    ///
    /// At least 1 — HTTP/1.1 requires `Host` (RFC 9112 §3.2).
    public let maxFieldCount: Int

    /// Maximum request body size before responding `413` (RFC 9110 §15.5.14).
    ///
    /// The global bound; a route's `bodyLimited(to:)` cap **replaces** it for requests matched to that
    /// route (Phase 1.2) — it may tighten or raise it. At least 0.
    ///
    /// Defaults to 16 MiB. It was 1 GiB, which was never a bound anybody could survive reaching: a
    /// buffered body is accumulated in memory before the handler sees an octet of it, so the default
    /// invited one request to ask for a gibibyte of resident memory and *be within its rights*.
    /// ``highThroughput`` restores the old ceiling for a deployment that has measured it.
    public let maxBodySize: Int

    /// Maximum reassembled WebSocket message size in octets (RFC 6455 §5.4 — fragments buffer until
    /// the final frame), or `nil` to follow ``maxBodySize``.
    ///
    /// A dedicated knob because a WebSocket message cap and an HTTP request-body cap guard different
    /// traffic: raising one should not silently raise the other (message-reassembly memory
    /// exhaustion). At least 0.
    ///
    /// Defaults to 4 MiB, **explicitly**. The default used to be `nil`, and the coupling that
    /// expressed was the defect rather than the feature: it made the reassembly buffer inherit a 1 GiB
    /// HTTP body cap that nothing about WebSocket framing justified. `nil` still restores the
    /// coupling for a caller who wants exactly that, and is worth avoiding for the same reason.
    public let maxWebSocketMessageSize: Int?

    /// The enforced WebSocket message cap: ``maxWebSocketMessageSize`` when set, else ``maxBodySize``.
    public var effectiveWebSocketMessageSize: Int { maxWebSocketMessageSize ?? maxBodySize }

    /// Maximum size of an inbound decompressed body (gzip/brotli decompression bombs; CWE-409).
    ///
    /// Enforced by the opt-in `DecompressionMiddleware`, which is the only thing in the server that
    /// decodes an inbound `Content-Encoding`; a build without it never decompresses a request body.
    ///
    /// At least 0, and never below ``maxBodySize`` — a decompressed cap under the raw cap would refuse
    /// bodies that shrank on the way through, which is incoherent. Defaults to 64 MiB.
    public let maxDecompressedBodySize: Int

    /// Maximum decompressed-to-compressed size ratio for an inbound body (decompression bombs).
    ///
    /// Charged against the size the peer actually sent, so it bounds total amplification even when
    /// several codings are stacked. Enforced alongside ``maxDecompressedBodySize``. At least 1.
    public let maxDecompressionRatio: Int

    /// Maximum number of stacked inbound content codings (RFC 9110 §8.4.1).
    ///
    /// `Content-Encoding` is an ordered list and each entry costs a full decode pass, so an
    /// arbitrarily long list is CPU amplification from a single header (CWE-409). Real traffic uses
    /// one coding; the default of 2 leaves room for the legal `gzip, br` shape and refuses deeper
    /// nesting with `415 Unsupported Media Type`. At least 1.
    public let maxDecompressionLayers: Int

    // MARK: HTTP/2 & HTTP/3 limits

    /// Advertised + enforced `SETTINGS_MAX_CONCURRENT_STREAMS` — the per-connection open-stream bound.
    ///
    /// A stream-state exhaustion DoS guard (RFC 9113 §5.1.2, whose recommended floor is ≥100); default
    /// 128. Unlike the connection ceilings it is *not* permissive: one connection opening unbounded
    /// concurrent streams would exhaust memory, so it stays bounded even in a trusted environment.
    /// At least 1 — zero would deadlock the connection.
    public let maxConcurrentStreams: Int

    /// Maximum accepted frame payload size.
    ///
    /// RFC 9113 §4.2 fixes `SETTINGS_MAX_FRAME_SIZE` at 16,384 … 16,777,215 inclusive and makes a
    /// value outside it a `PROTOCOL_ERROR`. This is the one limit whose *floor* an engine cannot
    /// survive violating: a zero here frames nothing and the read loop makes no progress. It is
    /// enforced rather than documented, because it used to sail straight through.
    public let maxFrameSize: Int

    /// HPACK / QPACK dynamic table capacity in bytes (decompression bomb; RFC 7541 §4.2).
    ///
    /// At least 0 — zero disables the dynamic table, which is legal and meaningful.
    public let headerTableSize: Int

    /// Maximum `CONTINUATION` frames per header block (CONTINUATION flood, CVE-2024-27316).
    ///
    /// At least 1.
    public let maxContinuationFrames: Int

    /// Maximum `RST_STREAM` churn per ``streamResetInterval`` before `GOAWAY` (Rapid Reset,
    /// CVE-2023-44487).
    ///
    /// At least 1 — a budget of zero would `GOAWAY` on the first reset a client is entitled to send.
    public let maxStreamResetsPerInterval: Int

    /// Maximum cheap/abusive control-plane frames per ``streamResetInterval`` before `GOAWAY`.
    ///
    /// Counts the frames that are cheap to send but do no useful work — PING / SETTINGS (and their
    /// ACKs), PRIORITY, zero-length non-final DATA, and WINDOW_UPDATE on a closed stream — so a flood
    /// of them is a CPU-exhaustion DoS (CVE-2019-9513 PRIORITY, CVE-2019-9518 empty DATA). A completed
    /// request drains the budget and it decays each ``streamResetInterval``; kept separate from
    /// ``maxStreamResetsPerInterval`` so resets and control frames are bounded independently.
    /// At least 1.
    public let maxControlFramesPerInterval: Int

    // MARK: Transport→application handoff bounds (backpressure)

    /// Unconsumed octets a transport intake channel holds before the reader task parks.
    ///
    /// The reader parking is the backpressure: it stops calling `receive`, so the kernel buffer fills
    /// and the peer's TCP window closes. Bounds the HTTP/1.1 WebSocket intake and the HTTP/2 raw
    /// mailbox, which were previously lossy and unbounded respectively (2026-07-31 audit, F1/F3).
    /// At least 1 — a zero watermark parks the reader before it has read anything, which is a
    /// deadlock rather than backpressure.
    public let maxQueuedInboundBytes: Int

    /// Unconsumed chunks a transport intake channel holds before the reader task parks.
    ///
    /// A second, independent bound on the *ticket* count a merged mailbox can accumulate — a count of
    /// chunks does not bound memory, and a byte watermark alone does not bound ticket cardinality when
    /// a peer dribbles tiny frames. At least 1.
    public let maxQueuedInboundChunks: Int

    /// Undelivered hub broadcasts a single WebSocket connection queues before the oldest is dropped.
    ///
    /// Unlike transport octets, broadcasts may be dropped — but never silently: the drop is counted
    /// and the connection is closed with `1008` (RFC 6455 §7.4.1) rather than pretending it delivered.
    /// At least 1.
    public let maxQueuedBroadcasts: Int

    /// Undelivered broadcast *octets* one WebSocket connection queues before the oldest is dropped.
    ///
    /// A count bound says nothing about memory: at the default ``effectiveWebSocketMessageSize``,
    /// ``maxQueuedBroadcasts`` messages is unbounded retention per connection (2026-07-31
    /// performance addendum). This is the watermark that actually bounds it (CWE-770).
    ///
    /// Derived from ``maxQueuedInboundBytes`` rather than given its own knob, deliberately: the two
    /// are the inbound and outbound halves of the same per-connection handoff, so one number keeps a
    /// connection's total handoff retention bounded at 2× it and keeps the presets coherent without a
    /// second dial nobody would remember to move.
    public var maxQueuedBroadcastBytes: Int { maxQueuedInboundBytes }

    // MARK: HTTP/2 consumption-gated receive windows (backpressure)

    /// The advertised `SETTINGS_INITIAL_WINDOW_SIZE` — unconsumed octets one HTTP/2 stream may hold.
    ///
    /// On a consumption-gated stream (a streaming route or an RFC 8441 tunnel) the window is debited as
    /// the peer sends and credited back only as the *handler* takes each chunk, so this **is** the
    /// per-stream memory watermark — no parallel accounting (RFC 9113 §6.9, ADR 0006).
    ///
    /// In `1 ... 2_147_483_647` (RFC 9113 §6.9.1 caps a flow-control window at 2^31-1), and never
    /// above ``connectionReceiveWindow``, which binds first in any case.
    public let streamReceiveWindow: Int

    /// The connection-level receive window — unconsumed octets one HTTP/2 connection may hold, across
    /// every stream.
    ///
    /// The hard bound consumption gating buys: at most this many un-taken application octets exist per
    /// connection regardless of stream count, route body limit, or handler behavior. RFC 9113 §6.9.2
    /// fixes the initial value at 65,535 and SETTINGS cannot change it, so the engine raises it with a
    /// stream-0 `WINDOW_UPDATE` in its preface.
    ///
    /// Throughput cost: a window of `W` at round-trip time `T` ceilings one connection's *upload* at
    /// `W / T` — 1 MiB at 50 ms is ≈ 20 MB/s. ``highThroughput`` raises it 8×. In
    /// `1 ... 2_147_483_647` (RFC 9113 §6.9.1).
    public let connectionReceiveWindow: Int

    /// How long a gated HTTP/2 stream may hold receive credit without the handler consuming any of it.
    ///
    /// Consumption gating means one non-consuming handler holds the *shared* connection window and so
    /// stalls every sibling stream — that is HTTP/2's semantics, not a bug, but it must not be
    /// unbounded. A stream that makes no consumption progress across two sweeps of half this duration
    /// is reset with `ENHANCE_YOUR_CALM` (RFC 9113 §7) and its siblings continue. Strictly positive.
    public let bodyConsumptionTimeout: Duration

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
    /// At least 1.
    public let requestBodyWindowSize: Int

    /// The largest read-buffer capacity a persistent HTTP/1.1 connection keeps between requests.
    ///
    /// A *buffered* request body is accumulated in that buffer, so one large upload leaves an
    /// upload-sized allocation behind — and `removeAll(keepingCapacity:)` would then hand that peak to
    /// every later request on the connection, for as long as the peer keeps it open. Past this ceiling
    /// the storage is released instead and grows back geometrically, as it did on the connection's
    /// first request: a handful of allocations on the rare large request, against unbounded
    /// per-connection retention for the common small one (CWE-401-shaped). At least 0.
    public let keepAliveBufferCapacity: Int

    /// The enforced streaming chunked receive window: ``requestBodyWindowSize``, floored so a maximal
    /// framing line plus a full read always fits.
    ///
    /// The floor is what makes the window deadlock-free. `readLine` refuses a chunk-size / extension /
    /// trailer line once the unframed octets pass ``maxFieldSize``, so with strictly more room than
    /// that the decoder always either consumes or fails closed — it can never answer "need more" to a
    /// window that has no more to give (RFC 9112 §7.1.1, §7.1.2).
    ///
    /// The addend is ``Bounds/bodyWindowHeadroom``, which is also the room ``Bounds/fieldSize``
    /// reserves below `Int.max` — so this sum cannot overflow whatever `maxFieldSize` is set to
    /// (R5-VAL; it used to trap on `maxFieldSize == .max`, a value validation accepted).
    public var effectiveRequestBodyWindow: Int {
        max(requestBodyWindowSize, maxFieldSize + Bounds.bodyWindowHeadroom)
    }

    // MARK: Timeouts (Slowloris / slow-read defenses)

    /// Maximum time to receive a complete header section (Slowloris; → `408`).
    ///
    /// Strictly positive — a non-positive deadline expires before the read it bounds can start.
    public let headerReadTimeout: Duration

    /// Maximum idle time on a connection before it is closed.
    ///
    /// Strictly positive.
    public let idleTimeout: Duration

    /// Maximum idle time on a persistent HTTP/1.1 connection between requests.
    ///
    /// Strictly positive.
    public let keepAliveTimeout: Duration

    /// The rolling window over which ``maxStreamResetsPerInterval`` is measured.
    ///
    /// Strictly positive — a zero-width window measures nothing.
    public let streamResetInterval: Duration

    // MARK: Connection limits

    /// Maximum simultaneous connections from a single client address (→ `429`).
    ///
    /// At least 1, and never above ``maxConnections`` — a per-client ceiling above the global one
    /// cannot bind, and reading it as one is exactly the misconfiguration this clamp removes.
    /// Defaults to 64, down from 1,024: no legitimate client opens a thousand sockets to one origin,
    /// and the old value let a single peer occupy 1.5 % of the old global ceiling on its own.
    public let maxConnectionsPerClient: Int

    /// Maximum simultaneous connections across all clients — a global resource ceiling against FD /
    /// task exhaustion (audit T-F2).
    ///
    /// Connections beyond it are closed immediately. Tune up for high-concurrency deployments (and
    /// raise the process file-descriptor limit to match). At least 1.
    ///
    /// Defaults to 16,384, down from 65,536: the old default sat above the default file-descriptor
    /// limit on every platform this server targets, so the ceiling that actually bound the process was
    /// `EMFILE` — a ceiling with no `429`, no accounting, and no hysteresis. ``highThroughput`` raises
    /// it for a deployment that has raised `RLIMIT_NOFILE` to match.
    public let maxConnections: Int

    /// The fraction of ``maxConnections`` the live count must fall back to before a saturated accept
    /// source re-arms — hysteresis preventing suspend/resume churn at the ceiling (audit F8).
    ///
    /// Without it a server sitting exactly at ``maxConnections`` would suspend and re-arm its accept
    /// source on every single close — a `kevent`/`epoll_ctl` syscall storm at the worst moment.
    /// Clamped to `0...1` **here**, where the doc comment always claimed it was; `1.0` disables the
    /// hysteresis (re-arm on the first free slot). A value that is not a number becomes the default.
    public let acceptResumeRatio: Double

    /// Creates a set of limits, clamping each into the range its documentation states.
    ///
    /// An out-of-range value is repaired rather than refused, so no configuration mistake can leave an
    /// engine holding a limit it cannot operate under — a `maxFrameSize` of 0 is the sharp example: it
    /// used to pass straight through and stall the read loop. Cross-field invariants are re-established
    /// afterwards, in the direction that preserves what the operator asked for.
    ///
    /// Use ``init(validating:)`` when a silent repair would hide a configuration bug worth surfacing.
    public init(
        maxRequestLineLength: Int = 8 * 1_024,
        maxFieldSize: Int = 16 * 1_024,
        maxHeaderListSize: Int = 64 * 1_024,
        maxFieldCount: Int = 100,
        maxBodySize: Int = 16 << 20,  // 16 MiB
        maxWebSocketMessageSize: Int? = 4 << 20,  // 4 MiB, explicitly — not "follow maxBodySize"
        maxDecompressedBodySize: Int = 64 << 20,  // 64 MiB
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
        maxConnectionsPerClient: Int = 64,
        maxConnections: Int = 16_384,
        acceptResumeRatio: Double = 0.875
    ) {
        self.init(
            Draft(
                maxRequestLineLength: maxRequestLineLength,
                maxFieldSize: maxFieldSize,
                maxHeaderListSize: maxHeaderListSize,
                maxFieldCount: maxFieldCount,
                maxBodySize: maxBodySize,
                maxWebSocketMessageSize: maxWebSocketMessageSize,
                maxDecompressedBodySize: maxDecompressedBodySize,
                maxDecompressionRatio: maxDecompressionRatio,
                maxDecompressionLayers: maxDecompressionLayers,
                maxConcurrentStreams: maxConcurrentStreams,
                maxFrameSize: maxFrameSize,
                headerTableSize: headerTableSize,
                maxContinuationFrames: maxContinuationFrames,
                maxStreamResetsPerInterval: maxStreamResetsPerInterval,
                maxControlFramesPerInterval: maxControlFramesPerInterval,
                maxQueuedInboundBytes: maxQueuedInboundBytes,
                maxQueuedInboundChunks: maxQueuedInboundChunks,
                maxQueuedBroadcasts: maxQueuedBroadcasts,
                streamReceiveWindow: streamReceiveWindow,
                connectionReceiveWindow: connectionReceiveWindow,
                bodyConsumptionTimeout: bodyConsumptionTimeout,
                requestBodyWindowSize: requestBodyWindowSize,
                keepAliveBufferCapacity: keepAliveBufferCapacity,
                headerReadTimeout: headerReadTimeout,
                idleTimeout: idleTimeout,
                keepAliveTimeout: keepAliveTimeout,
                streamResetInterval: streamResetInterval,
                maxConnectionsPerClient: maxConnectionsPerClient,
                maxConnections: maxConnections,
                acceptResumeRatio: acceptResumeRatio
            )
        )
    }

    /// Returns a copy with the overrides `configure` applies, re-establishing every invariant.
    ///
    /// The replacement for field-by-field mutation. `limits.maxBodySize = n` used to be legal and
    /// bypassed every check the initializer had made; this routes the same edit back through the same
    /// clamp, so a set of limits is validated at every point in its life rather than only at birth.
    public func with(_ configure: (inout Draft) -> Void) -> Self {
        var draft = Draft(self)
        configure(&draft)
        return Self(draft)
    }

    /// A copy whose ``maxBodySize`` is `limit`, or `self` when `limit` is `nil`.
    ///
    /// The one legitimate reason the properties were ever mutated after construction: a matched route's
    /// `bodyLimited(to:)` cap **replaces** the global body bound for requests routed to it — it may
    /// raise the bound as well as tighten it (Phase 1.2; RFC 9110 §15.5.14). Naming the rule here keeps
    /// it in the type that owns the invariant rather than open-coded identically in two read loops, and
    /// sends the route's own number through the same clamp every other value passes.
    public func bodyLimited(to limit: Int?) -> Self {
        guard let limit else {
            return self
        }
        return with { $0.maxBodySize = limit }
    }

    /// The default limits — safe out of the box: conservative size/count/timeout guards and secure,
    /// non-throttling connection ceilings with a bounded 128-stream per-connection cap.
    public static let `default` = Self()

    /// A high-throughput / trusted-environment preset that raises the connection ceilings and restores
    /// the pre-CR-F15 size ceilings.
    ///
    /// The ceilings go far above any legitimate need so they never throttle a benchmark or a trusted
    /// internal peer. Use ONLY where the peer set is trusted — it disables the connection-exhaustion
    /// bounds that ``default`` provides, and puts the 1 GiB body cap back. ``maxConcurrentStreams``
    /// stays bounded (a memory bound, never a throughput one).
    public static let highThroughput = Self(
        maxBodySize: 1 << 30,  // 1 GiB — the old default, reachable in one word
        maxWebSocketMessageSize: 1 << 30,
        maxDecompressedBodySize: 1 << 30,
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
        maxBodySize: 4 << 20,
        maxWebSocketMessageSize: 1 << 20,
        maxDecompressedBodySize: 16 << 20,
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
        maxConnectionsPerClient: 16,
        maxConnections: 4_096
    )
}
