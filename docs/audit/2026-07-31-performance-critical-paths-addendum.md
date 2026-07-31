# Performance critical-path review addendum

Date: 2026-07-31  
Revision inspected: `f2b3602`  
Relationship: deeper follow-up to `2026-07-31-performance-critical-paths.md`

This addendum expands the first review into the runtime paths that received less attention there:
stream handoff, DispatchSource and QUIC transports, TLS, static files, multipart parsing,
compression/decompression, WebSocket fanout, authentication, caching, observability, and shutdown.
It also re-audits the HTTP/2 and HTTP/3 concurrency paths at the point where protocol events cross
into server tasks.

This is a review and execution plan. No production source was changed.

## Outcome

The highest-priority work is not another parser micro-optimization. Three correctness defects sit
directly on multiplexed hot paths:

1. byte-channel coalescing can create more wakeup tickets than dequeueable items, parking the sole
   HTTP/2 or WebSocket consumer on an intake item that does not exist;
2. the DispatchSource transport stores a concurrently parked read and write in one waiter slot, so
   either operation can overwrite the other;
3. an HTTP/3 encoder-stream receive can unblock a request on a different QUIC stream, but the server
   processes and sends it through the encoder stream's driver and drops actions for other stream IDs.

Those are P0 because they can stall or misroute otherwise valid concurrent traffic. The next tier is
bounded streaming and execution isolation: HTTP/1 request streaming still retains the full wire body,
decompression can eagerly allocate up to the configured cap, HTTP/3 bypasses TCP admission and drain
accounting, and arbitrary handler/file/crypto/compression work can run on a serial reactor.

A state-of-the-art target for this codebase should have:

- one owner for each connection's socket and protocol state;
- independently parallel application work per request or stream;
- bounded byte-based admission at connection, stream, and process scope;
- no reactor blocking on filesystem, compression, public-key crypto, logging sinks, or application
  work;
- one reactor timer facility rather than watchdog tasks per connection/operation;
- borrowed parsing and pooled owned buffers across the transport/protocol boundary;
- suspension only for real backpressure, application work, or deadlines—not for bookkeeping that can
  complete synchronously.

## Version and API gate

The deployment gate remains Swift tools 6.4, Swift 6 mode, macOS 15, and iOS 18. The proposed changes
do not require raising it.

- `Span`, `RawSpan`, `MutableSpan`, and `OutputSpan` are available at the current floor and are suitable
  for borrowed parser/frame views and direct initialization.
- `withUnsafeTemporaryAllocation` is available at the current floor and is the right storage for small
  temporary `iovec` arrays.
- `Synchronization.Mutex` and `Atomic` already build at the configured floor. They remain appropriate
  for cross-thread handoff, but loop-owned state should need neither.
- `InlineArray` requires the 26-generation operating systems. Use `ContiguousArray` with
  `reserveCapacity`, or temporary stack allocation, at the current floor. A future target raise merely
  unlocks the fixed-size spelling; it is not justified by this optimization.
- Unsafe pointer code is warranted only at the syscall/codec boundary. Keep it behind safe,
  length-carrying interfaces and test it under ASan/TSan.

## Scope and verification

The follow-up traced these production areas:

| area | paths reviewed |
|---|---|
| connection lifecycle | accept, admission, preferred executor, deadlines, shutdown |
| transports | kqueue/epoll, DispatchSource POSIX, Network.framework, portable TLS, QUIC |
| core parsing | request line, fields, chunking, multipart, request body collection |
| HTTP/1 | sniff, buffered and streaming request, serialization, file send |
| HTTP/2 | reader/wakeup bridge, flow control, request/response streaming, tunnels, scheduling |
| HTTP/3 | connection/stream driver, QPACK unblock, request streaming, QUIC lifecycle |
| WebSocket | intake, framing, compression, broadcast mailbox and hub |
| server features | routing, static files, precompressed variants, autoindex |
| middleware | limits, timeout, compression, decompression, cache, conditional requests |
| security/operations | Basic/JWT auth, sessions, request IDs, logging, metrics, tracing |
| measurement | microbenchmarks, macro harness, CI baseline behavior |

Verification performed:

- `swift test` passed from the repository root with no unexplained failures;
- the fresh deterministic `http1/RequestParser/realistic` benchmark completed at a median of about
  32 K instructions, 7 mallocs, 2.7 microseconds wall time, and 4.7 microseconds total CPU time on this
  host;
- the targeted multi-pattern benchmark invocation matched only that HTTP/1 benchmark, which is
  itself a benchmark selection/usability gap;
- wall-clock throughput results are not treated as decision-grade because the host was concurrently
  loaded during the review.

## P0 correctness and resource-safety findings

### P0.1 — Coalescing breaks the intake channel's wakeup invariant — RESOLVED (`29e313f`)

Locations:

- `Sources/Server/HTTPServer/BoundedByteChannel.swift:204-233`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2Reader.swift:36-53`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2.swift:102-110,135-144`
- `Sources/Server/HTTPServer/HTTPServer+WebSocket.swift:142-164,194-225`
- `Tests/Server/HTTPServerTests/BoundedByteChannelTests.swift:167-179`

The channel merges a send into the current tail without increasing `queued`. Both callers still yield
one `.inboundReady` ticket after every `send`. If two sends are coalesced before the sole consumer
runs, two tickets represent one queue item:

1. the first ticket dequeues the merged item;
2. the second ticket calls `next()` and parks;
3. the consumer cannot process responses, broadcasts, or other wakeup kinds until another network
   chunk or terminal event happens.

For an idle WebSocket this can stall an unrelated hub broadcast indefinitely. For HTTP/2 it can stall
outbound progress and produce a connection-level deadlock under an otherwise valid packet schedule.
The existing test proves byte preservation inside the channel but never composes coalescing with the
external ticket protocol.

Change:

- make `send` return whether it created a new dequeueable edge and yield only on that transition; or
- move edge notification into the channel so queue mutation and wakeup accounting are one invariant;
- as an immediate correctness containment, disable coalescing for externally ticketed consumers.

Regression test: enqueue two sub-threshold chunks before consuming, enqueue an unrelated response or
broadcast wakeup, and prove the consumer processes both without a third inbound byte.

**Resolution (`29e313f`).** Took the first two options together, so the accounting lives where the
queue mutation lives: `send`/`trySend` now return `Acceptance` — `.queued` (a new dequeueable item
exists, the caller owes exactly one ticket), `.absorbed` (merged into the tail, or handed straight to
a parked consumer, so no ticket is owed), `.refused` (nothing enqueued; for `trySend` this is the
pre-existing fail-closed signal). Both readers ticket only on `.queued`.

Coalescing was **kept**, not disabled. It exists so a peer dribbling one-octet frames cannot inflate
the mailbox ticket count up to the hard cap, and that is still worth having — the defect was the
accounting, not the merge.

Two regressions landed: a channel-level one asserting `.queued`/`.absorbed` exactly, and the
end-to-end one this section asks for. The latter forces the interleaving rather than hoping for it —
the WebSocket handler holds the pump until the reader has drained the wire, so the coalesce provably
happens before the pump dequeues — and it was verified red-first by restoring the unconditional
yield, at which point the broadcast never reaches the wire.

### P0.2 — DispatchSource read and write can overwrite one another's waiter

Location: `Sources/Transport/HTTPTransport/POSIXDispatch/POSIXDispatchConnection.swift:33-53,84-118,145-209`

`POSIXDispatchConnection` has independent read and write resumers but one
`Mutex<Waiter?>`. A parked read installs its source at lines 95-98; a blocked write replaces it at
lines 198-203. HTTP/2 deliberately has a continuous reader and a sole writer in separate tasks, so
simultaneous parking is a supported server state. The serial Dispatch queue serializes installation
closures, but it does not prevent the two asynchronous operations from remaining parked together.

Consequences:

- cancellation/close resumes at most one waiter;
- the overwritten source can remain armed while its continuation is no longer reachable from teardown;
- one read or write task may never resume;
- the comment that writes never overlap reads is false for multiplexed protocols.

Change: keep separate read/write waiter slots and cancel/resume both atomically during close. Enforce
one reader and one writer per connection independently. Add a test that fills the socket send buffer,
parks a write while a read is parked, then cancels and proves both operations terminate exactly once.

### P0.3 — HTTP/3 events and actions are handled by the wrong stream driver

Locations:

- `Sources/Server/HTTPServer/HTTPServer+HTTP3.swift:175-230,435-455`
- `Sources/Protocols/HTTP3/HTTP3Connection+Streams.swift:186-214`
- `Sources/Protocols/HTTP3/HTTP3Connection+Request.swift:388-435`
- `Tests/Protocols/HTTP3Tests/HTTP3DynamicQpackTests.swift:63-94`

Every inbound QUIC stream task calls one shared actor engine and then handles the returned global
events/actions using its own `stream`. QPACK encoder instructions can unblock a field section belonging
to a different request stream. The protocol test correctly proves that the request event surfaces from
the encoder-stream `receive`.

The server then calls `respondHTTP3(..., stream: currentEncoderStream, ...)`. `applyHTTP3` sends only
actions whose ID matches the current stream and silently drops other-ID actions in its default case.
The local comment that other-ID sends cannot occur conflicts with the tested QPACK behavior.

Change: introduce one per-connection dispatcher with a stream registry. Engine output must be routed
by the action/event stream ID into bounded per-stream mailboxes or directly to the registered stream
writer. Per-stream tasks may parse independent bytes, but no task may assume all output from an engine
call belongs to the input stream.

Regression test: run the existing blocked-QPACK scenario through the live server driver and prove the
handler runs once for the request stream and the response is written only there.

### P0.4 — HTTP/1 request “streaming” retains and copies the entire body

Locations:

- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:181-202`
- `Sources/Server/HTTPServer/HTTPServer+RequestStreaming.swift:52-118`

The body is exposed through an unbounded `AsyncStream<[UInt8]>`, but Content-Length input is appended to
the persistent connection buffer and copied into a new array for every yield. The chunked path keeps a
growing fully decoded body and emits copied deltas. A slow or abandoned consumer can therefore retain:

- the full encoded body in the connection buffer;
- the full decoded chunked body;
- every queued per-yield array;
- the connection buffer's high-water capacity across keep-alive requests.

This is not bounded streaming, and the default large body limit makes it a practical memory-exhaustion
path.

Change: use a consumption-driven, bounded rolling parser. Read directly into reusable storage, expose
owned chunks whose total bytes are watermarked, discard consumed framing bytes, and stop replenishing
transport flow control while the consumer is saturated. The parser should retain only a bounded
framing carry plus the configured queued-body budget.

### P0.5 — HTTP/3 bypasses server admission, deadlines, and graceful drain

Locations:

- `Sources/Server/HTTPServer/HTTPServer.swift:82-99,143-185`
- `Sources/Server/HTTPServer/HTTPServer+HTTP3.swift:105-150,303-351`
- `Sources/Server/HTTPServer/HTTPServer+Shutdown.swift:17-39`

TCP connection counts are enforced inside `accept`, after a task is created. QUIC connections use a
separate loop that creates one task per connection without the global or per-client counts. Each QUIC
connection then creates a task for every inbound stream. The path has no matching application
idle/header/body deadline per stream, and the shutdown registry contains TCP connections only.

There is a second correctness edge in streaming requests: EOF, reset, or receive failure can leave
`ended == false`; the code still finishes the handoff, waits for the handler, and emits a response.
That treats a truncated request body as complete.

Change:

- unify TCP and QUIC admission in a process-wide connection/stream/byte budget;
- reject before creating an unbounded serve task where the transport permits it;
- track QUIC connections and streams for GOAWAY/drain/forced close;
- attach header/body/idle deadlines to request streams;
- reset/cancel a streaming request unless a valid `requestEnd`/FIN state was observed.

### P0.6 — Multipart parsing is copy-heavy, superlinear, and accepts false delimiters

Location: `Sources/Core/HTTPCore/MultipartFormData.swift:54-184`

The parser prepends CRLF to the entire body, copies every part, copies its header section and body
again, and uses a naive nested substring search. An adversarial body containing long partial boundary
prefixes costs `O(body size × boundary size)`.

After finding `\r\n--boundary`, the parser searches for the next CRLF anywhere after the boundary
instead of requiring the delimiter suffix immediately. A line such as
`\r\n--boundaryJUNK\r\n` can therefore be accepted as a delimiter and split file content incorrectly.
Boundary length/charset, part count, per-part headers, and aggregate output have no independent caps.
Parameter parsing also splits on every semicolon, including semicolons inside quoted values.

Change:

- first fix delimiter grammar and bound boundary length/characters;
- add part-count, part-header-byte, and aggregate retained-byte limits;
- replace naive search with a linear-time streaming matcher such as Two-Way or KMP;
- operate on borrowed spans and stream large parts to a consumer/file rather than returning copied
  bodies;
- parse quoted parameters with a small state machine.

Add adversarial tests for partial-prefix floods, junk delimiter suffixes, quoted semicolons, too many
parts, oversized headers, truncated closing boundaries, and cancellation.

### P0.7 — Decompression eagerly collects and may allocate the full cap

Locations:

- `Sources/Server/HTTPServer/Middleware/DecompressionMiddleware.swift:44-78`
- `Sources/Server/HTTPServer/Middleware/Inflate.swift:114-157`

The middleware calls `body.collect()` before checking whether `Content-Encoding` exists. Merely
installing it turns every streamed request into a buffered request. For supported content it allocates
`maxOutput + 1` bytes before decoding; default-scale limits can therefore produce an enormous
per-request allocation even for a small compressed input. A public initializer can accept
`Int.max`, making `maxOutput + 1` overflow and trap.

The zlib-wrapper fallback strips the header and Adler-32 trailer without validating either. Multiple
content codings are not parsed.

Change:

- inspect encoding before touching the body and forward the original stream unchanged when absent;
- reject invalid configuration at initialization;
- implement incremental decompression with geometric, bounded output chunks and a process-wide
  decompression CPU/byte budget;
- validate wrapper metadata/checksums and parse the coding list correctly;
- run compression work on a bounded CPU executor, never the I/O reactor.

## P1 correctness and security findings

### Static-file validator and negotiation correctness

Locations:

- `Sources/Server/HTTPServer/FileResponder.swift:125-159,232-239`
- `Sources/Server/HTTPServer/FileResponder+Precompressed.swift:35-70`

The “strong” ETag contains only file size and whole-second modification time. A same-size rewrite
within one second can receive the same strong validator despite different bytes. Mark a metadata-only
validator weak, include higher-resolution identity metadata where portable, or use a cached content
digest when strong validation is required.

A precompressed 304 omits `Vary: Accept-Encoding`, even though its corresponding 200 includes it.
Negotiation reparses the header per candidate, gives Brotli fixed precedence rather than comparing
quality values, recognizes only the exact spelling `q=0`, and does not fully enforce
`identity;q=0`. Parse once into a fixed preference structure and generate invariant representation
headers for both 200 and 304.

### Authentication and logging trust boundaries

Locations:

- `Sources/HTTPAuth/BasicAuthMiddleware.swift:28-94`
- `Sources/HTTPAuth/JWT.swift:124-186`
- `Sources/Server/HTTPServer/Middleware/AccessLogMiddleware.swift:24-34`

Basic auth creates a random comparison key per middleware and computes two HMACs for the supplied
username plus two for the password on every request. Public-key JWT verification, JSON decoding, and
these HMACs currently inherit the request execution placement, which may be the serial reactor.
Precompute expected Basic-auth digests and compute one candidate digest per field while still
evaluating both comparisons. Move public-key verification to bounded CPU work.

JWT temporal checks reject non-finite claims but do not validate a non-finite `now` or `leeway`.
Because comparisons with NaN are false, an invalid clock/leeway input can bypass temporal rejection.
Require finite `now` and finite, nonnegative leeway.

Access logging records `request.path`, including its query string. Query parameters routinely carry
tokens or personal data. Log a normalized path without query by default and require explicit,
redacted opt-in for query fields. A synchronous log sink also must not run on the reactor.

### Hard bounds must preserve their advertised semantics

Locations:

- `Sources/Core/HTTPConcurrency/SharedBoundedLRU.swift:35-50`
- `Sources/Server/HTTPServer/RequestBody.swift:24-42`
- `Sources/Server/HTTPServer/Middleware/BodyLimitMiddleware.swift:20-38`

`SharedBoundedLRU(capacity: 0)` internally forces capacity to at least one, so a requested disabled/zero
cache still retains an entry. Preserve zero as zero.

`RequestBody.collect()` grows without reserving from a known Content-Length and without its own cap;
`BodyLimitMiddleware` enforces a limit by collecting the entire stream. A streaming limit should count
and fail while forwarding chunks. Transformation middleware needs its own post-transform limit because
the wire-body route limit is not sufficient.

## P1 throughput and memory findings

### Execution topology is the largest throughput ceiling

Locations:

- `Sources/Server/HTTPServer/HTTPServer.swift:168-174`
- `Sources/Transport/HTTPTransport/Abstraction/TransportConnection.swift:100-116`

`withTaskExecutorPreference` encloses the connection's full structured serve hierarchy. On a loop-backed
transport, routing, middleware, handlers, filesystem calls, compression, cryptography, logging, and
some streaming producers can all inherit a serial reactor. One CPU-heavy or blocking operation then
stalls every connection on that shard.

Retain reactor affinity only for socket/protocol mutation. Dispatch immutable requests plus a resolved
handler plan to a bounded application executor. Return completions through a bounded mailbox to the
owning reactor. A small certified synchronous handler may opt into inline execution only when it has a
nonblocking, allocation-bounded contract.

Maximum parallelism here means parallel independent requests, not an unbounded task count. Bound both
queued task count and retained request/response bytes.

### Accept, reactor, and timeout mechanics perform avoidable work

Locations:

- `Sources/Server/HTTPServer/HTTPServer.swift:82-99`
- `Sources/Server/HTTPServer/HTTPServer+Timeout.swift:59-94`
- `Sources/Transport/HTTPTransport/POSIXKqueue/KqueueEventLoop.swift`
- `Sources/Transport/HTTPTransport/POSIXEpoll/EpollEventLoop.swift`

The TCP accept loop creates a task before applying admission. Under an accept storm this allocates
wrappers/tasks for connections that will immediately close. Apply admission at the accept edge and
bound the accepted-connection channel.

Each connection/operation owns deadline state plus watchdog tasks. Updating a deadline does not wake an
existing sleep when the new target is earlier. Replace this with one timer heap or hashed wheel per
reactor and generation tokens. This removes task creation, sleeps, per-I/O deadline locks, and late
enforcement.

The event loops use a mutex-protected dictionary for parked operations and a rearm syscall around
read/write suspension. Move registry state under sole loop ownership and batch interest changes. Their
inbox drains copy the array into a local and then retain both storages because of copy-on-write; use a
double buffer/ring or swap that truly reuses capacity. Put a job/time budget on each drain so preferred
executor work cannot starve I/O readiness.

Shutdown always sleeps the full deadline once any connection is initially present and then closes
stragglers sequentially. Signal when the active set reaches zero and close remaining connections in a
bounded task group at the deadline.

### Transport buffers and copies scale poorly with connection count

The loop-backed raw connection lazily retains a 16 KiB scratch buffer per connection and copies from it
into the caller's array. `receive(into:)` should reserve a writable tail and read directly into it, or
use an owned buffer pool. At the default 65,536 active connections, a 16 KiB scratch alone is 1 GiB
after all connections read once.

The send path constructs a heap-backed `[iovec]` and enters a continuation even when the syscall
completes immediately. Use temporary stack allocation for the vector and an immediate synchronous
result before installing a waiter.

Portable TLS adds plaintext and ciphertext scratch buffers and pumps bytes through memory BIOs,
introducing more copies and roughly another 32 KiB of user buffer state after activation. Verify a
nonblocking socket-BIO integration or an equivalent direct record path before replacing it; TLS
correctness and library thread-affinity invariants must remain explicit. Network.framework sends also
copy into `Data`; avoid coalescing two buffers unless its reduced send overhead wins for the measured
size/transport.

### HTTP/1 repeats parsing, routing, and allocation work

Locations:

- `Sources/Protocols/HTTP1/HeaderParser.swift:44-100`
- `Sources/Core/HTTPCore/HTTPFieldName.swift:89-100`
- `Sources/Server/HTTPServer/HTTPServer.swift:121-140`
- `Sources/Server/HTTPServer/HTTPServer+Streaming.swift:90-110`

Header parsing scans line structure, colon, name bytes, and value bytes in separate passes. Mixed-case
names create both original and canonical strings. Fuse validation with delimiter scanning and intern
common field names behind a compact `HeaderKind`, while preserving original spelling only when the
public API requires it. The measured seven allocations in the realistic parser are the baseline to
beat; changes need instruction and allocation evidence.

Routing/body policy/streaming selection and final handler dispatch resolve the route separately. HTTP/2
and HTTP/3 can resolve three times, and a hot reload can swap responders between policy and dispatch.
Read one immutable responder snapshot and produce a `DispatchPlan` containing handler, parameters,
body limit, streaming policy, and WebSocket metadata. Resolve once per request.

HTTP/1 chunked responses build a hex `String`, an array, and a coalesced chunk per body chunk. Use a
reusable prefix buffer and three-vector write for raw TCP; retain a measured coalescing threshold for
TLS/Network.framework where many tiny records/sends can cost more than one copy.

### HTTP/2 copies each frame and over-schedules streaming work

Locations:

- `Sources/Protocols/HTTP2/HTTP2Connection.swift:228-287,350-375`
- `Sources/Protocols/HTTP2/HTTP2FrameDecoder.swift:41-59`
- `Sources/Protocols/HTTP2/HTTP2Connection+FlowControl.swift:100-120,205-235`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2Streaming.swift`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2RequestStreaming.swift`

Inbound bytes are appended to a connection array, frames are accumulated in an intermediate event
array, each payload is copied, and DATA is copied again. `removeFirst` also shifts storage. Decode one
borrowed frame view at a time from a rolling buffer and copy only payload that must outlive the borrow.
Return frame storage capacity to a pool rather than replacing arrays with fresh empty values.

Completed stream eviction uses `removeFirst` on an array. Writable-stream selection scans and sorts
ready streams. Replace them with a ring and eight urgency queues. A stable stream slab/open-addressed
table would also avoid repeated dictionary remove/reinsert churn.

Request streaming uses unbounded `AsyncStream` storage and replenishes HTTP/2 flow-control windows
independently of application consumption. Tunnel and response mailboxes are similarly not globally
byte-bounded. Gate WINDOW_UPDATE on consumed bytes and impose connection-wide queued inbound/outbound
budgets in addition to per-stream limits.

Each streaming response can create a producer task, relay actor, and watchdog; relay release scans all
relays and awaits each actor after engine mutations. Prefer a pull-based iterator owned by the
connection scheduler, indexed ready relays, and reactor timers. A slow response stream should receive
RST_STREAM after its own deadline, not force the entire multiplexed connection closed.

### HTTP/3 centralizes too much and QPACK uses linear structures

Locations:

- `Sources/Protocols/HTTP3/HTTP3Connection+Streams.swift:189-266`
- `Sources/Protocols/HTTP3/HTTP3Connection+Request.swift:388-435`
- `Sources/Protocols/QPACK/QPACKDynamicTable.swift:84-116`
- `Sources/Protocols/QPACK/QPACKEncoder+Dynamic.swift:104-205`
- `Sources/Protocols/QPACK/QPACKEncoder+DecoderStream.swift:45-65`

One actor serializes receive work for every QUIC stream. Parse independent stream framing outside the
shared actor; confine the actor or connection owner to QPACK/control settings and global limits. Keep
the per-connection output dispatcher required by P0.3.

Frame decode copies payloads and shifts stream buffers. Apply the same rolling-buffer/borrowed-frame
model as HTTP/2.

The QPACK dynamic table stores newest entries at the front of an array, so insertion and lookup are
linear. Recent-field tracking uses `contains`, `firstIndex`, and `removeFirst`; blocked-stream counts
scan outstanding sections; unblocking scans every stream after inserts. Port the HPACK ring/hash-index
approach, maintain counters incrementally, store per-stream acknowledgements in rings, and index
blocked sections by required insert count.

The QPACK benchmarks still cover static field-section encoding despite dynamic-table support now being
implemented. Add warm insert/reference/acknowledgement, blocked/unblock, eviction, and adversarial
lookup workloads.

### WebSocket fanout is bounded by count, not retained bytes

Locations:

- `Sources/Server/HTTPServer/WebSocketBroadcastMailbox.swift`
- `Sources/Server/HTTPServer/WebSocketHub.swift`
- `Sources/Protocols/WebSocket/WebSocketConnection.swift`

The broadcast mailbox caps messages but not bytes. With a large allowed message size, many distinct
messages can retain far more memory than the count implies. Add a byte watermark and make the drop or
disconnect policy explicit.

The hub is one actor and performs O(subscriber count) fanout while isolated. Removal scans all topics.
Shard by topic, snapshot subscriber sinks before dispatch, and keep a reverse token index. Do not await
subscriber work inside the hub.

Framing still follows append → decoded event arrays → `removeFirst`, and outbound/fragments frequently
replace buffers instead of retaining capacity. Permessage-deflate allocates scratch and copies input
and output per message. Reuse bounded buffers, write framing directly into output storage, and apply a
measured compression threshold. The handshake currently parses extension negotiation more than once.

### Static serving performs blocking filesystem work on the reactor

Locations:

- `Sources/Server/HTTPServer/FileResponder.swift:73-83,164-212`
- `Sources/Server/HTTPServer/RootDirectory.swift:77-116`
- `Sources/Server/HTTPServer/FileRegionStreamer.swift:30-55`
- `Sources/Transport/HTTPTransport/Abstraction/TransportConnection+SendFile.swift:20-55`
- `Sources/Server/HTTPServer/FileResponder+Autoindex.swift:40-120`

Path walking, `openat`, `fstat`, small-file `pread`, streaming `pread`, and directory enumeration are
synchronous inside the handler hierarchy and can therefore block a reactor. Use a dedicated bounded
blocking-I/O pool and a metadata/descriptor cache with explicit invalidation bounds. Raw HTTP/1 can
retain `sendfile`; TLS/H2/H3 need pooled owned buffers or a platform-specific zero-copy facility where
the security layer supports it.

Fallback file streaming copies each 64 KiB slice into a new array. Pass ownership of a pooled chunk or
write from a borrowed buffer before reuse.

Autoindex scans and stats every entry, sorts `O(n log n)`, and builds the entire HTML body. HEAD performs
the same expensive work to compute length. Keep it disabled by default, cap entries/work, paginate or
stream, and URL-encode href path components rather than applying only HTML escaping.

### Middleware and observability redefine the hot path

Locations:

- `Sources/Server/HTTPServer/Middleware/TimeoutMiddleware.swift:55-90`
- `Sources/Server/HTTPServer/Middleware/CompressionMiddleware.swift`
- `Sources/Server/HTTPServer/Middleware/ResponseCache.swift`
- `Sources/HTTPObservability/MetricsSink.swift:35-50`
- `Sources/HTTPObservability/LoggingMiddleware.swift:28-50`

Timeout middleware creates competing tasks plus a timer per request and cannot actually return while an
uncooperative structured child ignores cancellation. Propagate a request deadline and enforce it at
transport/application boundaries using the reactor timer service.

Compression reparses `Accept-Encoding`, buffers whole responses, and performs synchronous CPU work.
Use a fixed parser, streaming compression, an off-reactor CPU budget, and a bounded cache for stable
compressed representations.

Response caching uses a global mutex and a separate linked-LRU implementation despite the shared
bounded LRU primitive. Its cost omits keys/headers, key construction allocates, revalidation tasks are
not supervised, and one Vary variant can displace another. Consolidate on a sharded bounded cache with
complete byte accounting and supervised single-flight revalidation.

Metrics constructs dimensions/status strings and retrieves new counter/timer handles per response.
Cache handles behind bounded method/status IDs. Logging constructs metadata dictionaries and path
strings per request. More importantly, metrics/logging/tracing currently end when the responder
returns, before serialization, streaming, socket backpressure, and send failure. Add server lifecycle
hooks and report handler latency separately from time-to-first-byte and time-to-last-byte.

## Feature-completion gaps exposed by the hot-path review

These are not cosmetic optimizations; they are required for a complete high-throughput server:

1. genuinely incremental, consumption-gated request bodies for HTTP/1, HTTP/2, and HTTP/3;
2. unified TCP/QUIC admission, stream limits, deadlines, GOAWAY, drain, and forced shutdown;
3. a correct per-connection HTTP/3 cross-stream dispatcher;
4. streaming multipart and compression/decompression with independent resource limits;
5. byte-bounded HTTP/2 tunnel/request/response queues and WebSocket broadcast queues;
6. full response-lifecycle observability, including stream and transport failure;
7. correct representation negotiation/validators for static and precompressed files;
8. benchmark coverage for warm multiplexing, backpressure, slow peers, and memory at connection scale.

## Target architecture

```text
accept/QUIC listener
    |
    +-- global + per-peer connection/stream/byte admission
    |
    v
reactor shard: fd + protocol owner + timer heap + write scheduler
    |
    +-- borrowed parse/frame views; copy only values crossing the owner boundary
    |
    +-- immutable DispatchPlan -----------------> bounded application/CPU executor
    |                                                 |
    |                                                 +-- handler / auth crypto
    |                                                 +-- compression
    |                                                 `-- blocking filesystem pool
    |                                                        |
    +<--------------- bounded completion/body mailboxes <----+
    |
    +-- H1 ordered writer
    +-- H2 urgency queues + byte-aware flow control
    `-- H3 per-stream registry + connection-wide QPACK/control owner
```

There should normally be no `await` while mutating reactor-owned state. An operation either completes
immediately or records a compact waiter and returns control to the loop. Awaiting is appropriate at
the application boundary, a full bounded queue, socket backpressure, or a deadline. Locks are
appropriate only for cross-owner transfer; they should not protect state that already has one owner.

## Execution plan

### Phase 0 — Correctness before optimization

1. Fix channel edge notification and add HTTP/2/WebSocket integration regressions.
2. Split DispatchSource read/write waiter state and test concurrent park/cancel.
3. Build the HTTP/3 stream registry/dispatcher and add the blocked-QPACK server regression.
4. Reject truncated H3 streaming requests.
5. Fix multipart delimiter grammar and impose conservative hard bounds.
6. Validate decompression caps against overflow and avoid collecting uncoded bodies.
7. Correct static validator/Vary/encoding negotiation semantics.

Exit condition: all existing tests plus the adversarial regressions pass under debug, release, ASan,
and TSan where supported.

### Phase 1 — Establish trustworthy measurements and execution isolation

1. Add warm end-to-end H1/H2/H3 benchmarks and commit instruction/malloc/RSS baselines.
2. Add equivalent bare-framework and realistic-stack macro suites.
3. Split reactor work from bounded application, crypto/compression, and blocking-file executors.
4. Move admission before task creation and unify QUIC accounting.
5. Replace watchdog tasks with per-reactor timers.

Exit condition: reactor utilization, handler queue depth, active bytes, and tail latency are observable;
no performance claim is accepted without before/after distributions on an idle host.

### Phase 2 — Eliminate transport and parsing copies

1. Direct-receive into reserved output storage and pool connection/frame buffers.
2. Avoid continuations on immediate send success and use stack `iovec` storage.
3. Fuse HTTP/1 header validation and route exactly once into a `DispatchPlan`.
4. Decode HTTP/2 and HTTP/3 frames as borrowed views from rolling buffers.
5. Validate a lower-copy portable TLS integration without weakening TLS invariants.

Exit condition: allocation counters demonstrate the reduction and peak RSS is bounded at 1 K, 10 K,
and the configured maximum idle connections.

### Phase 3 — Multiplexed scheduling and streaming

1. Gate HTTP/2 WINDOW_UPDATE on body consumption and enforce connection-wide byte budgets.
2. Introduce H2 urgency queues, stable stream storage, and per-stream deadline resets.
3. Split H3 stream parsing from shared QPACK/control state.
4. Replace QPACK front arrays/scans with rings, indexes, and blocked-section ordering.
5. Make multipart and compression pipelines incremental and cancellation-aware.

Exit condition: one slow stream does not block siblings; retained bytes remain within the declared
budget; cancellation frees queued storage promptly.

### Phase 4 — Product-path efficiency

1. Move static filesystem work off reactors and add a bounded metadata/content cache.
2. Shard WebSocket fanout and byte-bound every mailbox.
3. Consolidate caches and cache metrics handles.
4. Precompute Basic-auth comparison state and isolate JWT verification.
5. Instrument handler, first-byte, last-byte, and transport-failure lifecycles separately.

## Benchmark and adversarial matrix

| workload | required dimensions |
|---|---|
| HTTP/1 | keep-alive, pipelining, realistic fields, streaming upload, chunked response |
| HTTP/2 | 1/16/100 concurrent streams, priorities, slow upload, slow download, reset |
| HTTP/3 | concurrent streams, QPACK dynamic/block/unblock, stream reset, migration if supported |
| TLS | handshake/resumption, 1 B/1 KiB/64 KiB bodies, slow writer, portable vs platform TLS |
| static | metadata hot/cold, small/sendfile/streamed, range, precompressed, large directory |
| WebSocket | frame sizes, fragmentation, compression, 1/1 K subscribers, slow subscriber |
| middleware | bare, routing, cache hit/miss, auth, compression, logging/metrics enabled |
| resource | 1 K/10 K/limit idle connections, accept flood, decompression bomb, multipart prefix flood |

For each relevant change record:

- instructions and mallocs per operation;
- CPU time and wall time distributions;
- throughput and p50/p95/p99/p99.9 at fixed concurrency;
- peak and steady RSS, bytes queued by class, and connection-scale slope;
- reactor busy time, executor queue depth, syscalls, context switches, and lock contention.

Establish each host's noise floor before setting CI thresholds. Then gate statistically meaningful
regressions against committed baselines rather than merely checking that the benchmark harness runs.
The current CI is broad and valuable, but no committed benchmark baseline was found, so it cannot yet
reject performance drift.

## Recommended immediate order

The first three fixes should be the channel wakeup invariant, DispatchSource dual waiters, and the
HTTP/3 cross-stream dispatcher. They are small enough to isolate and have deterministic regression
tests. Then fix bounded streaming/decompression and QUIC lifecycle accounting before changing the
execution topology. Only after those invariants are locked should buffer pooling, borrowed frames,
QPACK structures, and parser fusion be benchmarked and merged.
