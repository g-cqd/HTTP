# Performance critical-path investigation

Date: 2026-07-31  
Revision inspected: `7200428` plus the working-tree changes present during the review  
Scope: accept/admission, the Darwin kqueue backbone, HTTP/1.1, HTTP/2, HTTP/3, routing,
middleware, response serialization, timeout machinery, and benchmark validity

This is an investigation and execution plan, not a set of performance claims. No production source
was changed by this review. While the review was running, uncommitted work appeared in
`HTTPLimits.swift` and the WebSocket mailbox implementation. Those edits were preserved. Findings
below distinguish the still-unbounded HTTP/2 mailbox from the WebSocket path that is already being
reworked.

## Verdict

The server has several strong foundations: sans-I/O protocol engines, bounded parsers, `RawSpan`
parsing, a reused HTTP/1 response buffer, `writev`, `sendfile`, per-core kqueue shards, and structured
cancellation. It is not yet at a state-of-the-art performance architecture.

The largest remaining constraints are not isolated byte-loop tricks:

1. Every active kqueue connection retains a 16 KiB read scratch buffer and owns watchdog/task state.
   The default 65,536-connection ceiling therefore implies a 1 GiB scratch-buffer payload floor after
   those connections attempt their first read, before tasks, input buffers, dictionaries, closures, and
   protocol state. The `highThroughput` ceiling of 1,048,576 connections implies 16 GiB of scratch
   payload alone.
2. `withTaskExecutorPreference` pins the entire structured task hierarchy, including arbitrary
   application handlers, to a serial reactor. This wins the trivial no-hop benchmark but allows one
   CPU-heavy or blocking handler to stall every connection assigned to that shard.
3. The kqueue steady-state path performs dictionary/`Mutex` bookkeeping and a separate `kevent`
   registration syscall whenever a read or write parks. The send path also creates and resumes a Swift
   continuation even when `write`/`writev` completes immediately.
4. HTTP/1 routing is performed once to select body policy and again to dispatch the handler. Both
   passes split the path into a fresh `[Substring]` and linearly scan routes.
5. HTTP/2 and HTTP/3 copy every decoded frame payload into a new array. HTTP/2 additionally crosses an
   unbounded `AsyncStream` mailbox, and both engines build intermediate event/action arrays.
6. The committed benchmarks do not yet measure the actual warm server hot path. The HTTP/1 serializer
   benchmark uses the allocating coalescing API, while the server uses a reused head buffer plus
   scatter/gather. HTTP/2 and HTTP/3 “respond” benchmarks create a new connection and decode a request
   every iteration.

The shortest route to materially better throughput is:

1. establish representative steady-state benchmarks;
2. remove the per-connection scratch and per-successful-write continuation;
3. compile routing/body policy/handler dispatch into one immutable plan;
4. move timeouts into each reactor;
5. make reactor state loop-owned and batch kqueue changes;
6. then remove frame and buffer copies from HTTP/2 and HTTP/3.

## Version and availability gate

The package uses Swift tools 6.4, Swift 6 language mode, macOS 15, and iOS 18
(`Package.swift:1,29-42,115-120`). The inspected toolchain is Apple Swift 6.4.

Apple documentation was checked for the load-bearing APIs:

- `withTaskExecutorPreference` and `TaskExecutor` are available from macOS 15/iOS 18. The preference
  applies to the structured task hierarchy and the operation immediately hops to that executor. The
  current use is deployment-safe, but its hierarchy-wide scope is exactly why application work is
  pinned to the reactor.
- `withUnsafeTemporaryAllocation(of:capacity:_:)` is available below this deployment floor and is the
  appropriate deployable storage for the two-element `iovec` call.
- `Span`, `RawSpan`, `MutableSpan`, and `OutputSpan` are usable at this package's floor with the current
  toolchain.
- `InlineArray` requires the 26-generation operating systems. Do not raise the package floor merely to
  use it. A target raise would unlock a simpler fixed-size `iovec` representation, but
  `withUnsafeTemporaryAllocation` is the correct current fallback.

## Measurement snapshot

### Host qualification

The host had load averages around 12/10/9 on 10 logical cores while unrelated audio, compiler, and
Xcode processes consumed multiple cores. A new live RPS or tail-latency number from that environment
would not be decision-grade, so this review did not manufacture one.

The deterministic benchmark metrics below are useful as a baseline. Wall-clock and throughput columns
from the same run are intentionally excluded.

| benchmark | p50 instructions | p50 mallocs | interpretation |
|---|---:|---:|---|
| HTTP/1 realistic request parse | ~32 K | 7 | actual parser fixture, 11 realistic fields |
| HTTP/1 response `serialize` | ~23 K | 9 | allocating/coalescing API, not the server's reused hot path |
| HTTP/2 connection `respond` | ~97 K | 36 | cold connection + request decode + response |
| HTTP/3 connection `respond` | ~66 K | 27 | cold connection + request decode + response |
| HTTP/2 frame decode | ~2.3 K | 1 | the payload array allocation occurs once per frame |
| HTTP/3 frame decode | ~2.4 K | 1 | the payload array allocation occurs once per frame |
| warm HPACK response encode | ~13 K | 1 | useful isolated encoding baseline |
| QPACK field-section encode | ~112 K | 1 | current benchmark fixture; inspect by field shape before use |

The malloc interposer reports zero allocations for the short mixed-case field-name fixture because
small strings fit inline. That does not invalidate the structural duplication for longer field names.

Historical loopback results under `Benchmarking/Django/results/_table.tsv` report 172,542 RPS for the
plaintext path, 154,951 for routing, and 91,447 for the middleware scenario. These are historical
artifacts, not a verified baseline for revision `7200428`, and their provenance differs from the
current machine. They are useful only as a signal that routing and especially middleware deserve
first-class benchmarks.

### Throughput budget

On the current six-performance-core machine, 200,000 requests/s permits at most 30 microseconds of CPU
per request if all six P-cores are saturated:

`6 CPU-seconds / 200,000 requests = 30 µs CPU/request`

At 70% CPU, the budget is 21 microseconds. This arithmetic is not a measured server result; it explains
why duplicated dispatch, several locks, a continuation, and avoidable allocations are material at this
target.

## Target execution model

Maximum parallelism does not mean maximum tasks or threads. It means serializing only state that must
be ordered while allowing independent application work to run concurrently.

```text
dedicated acceptor
      |
      v
reactor shards (one owner for fd, parse state, protocol state, writes, timers)
      | \
      |  \ certified bounded synchronous handler
      |   `--------------------------------------> inline response
      |
      `---- immutable request + dispatch plan ----> application executor
                                                     |
                  bounded completion mailbox <------'
                             |
                             v
                         owning reactor
```

Properties:

- no locks for reactor-owned connection, registration, timer, or protocol state;
- one synchronized cross-thread inbox per reactor, drained in batches;
- no application `await` or blocking call on a reactor unless the handler explicitly opts into a
  bounded synchronous/inline contract;
- HTTP/2 and HTTP/3 handlers may run in parallel by stream, while HPACK/QPACK, flow control, and wire
  ordering remain single-owner;
- one timer structure per reactor, not one watchdog task per connection;
- bounded mailboxes provide backpressure rather than buffering an unbounded amount of work.

## Critical path: HTTP/1 over kqueue

For a non-pipelined keep-alive request, the current path is approximately:

```text
kevent readiness
  -> registry Mutex + dictionary remove
  -> read into connection's 16 KiB scratch under Mutex
  -> copy scratch into server input buffer under Mutex
  -> deadline Mutex updates
  -> request-line/header parse and owned String/HTTPField construction
  -> responder Mutex + route resolution for body policy
  -> responder Mutex + Router.respond
  -> second path split and route scan
  -> arbitrary async handler on the serial kqueue TaskExecutor
  -> response-field copy-on-write for automatic Content-Length
  -> heap-backed [iovec]
  -> unsafe continuation + resumer Mutex
  -> writev
  -> deadline Mutex updates
  -> register one-shot read interest with another kevent syscall
```

The three semantic suspension points—wait for input, run an async handler, wait for output—are
reasonable. The supporting locks, copies, continuation, route duplication, and per-connection timer
task are not required by HTTP.

## Ranked findings and proposed changes

### P0 — Make the benchmark suite capable of proving improvement

Locations:

- `Benchmarking/Benchmarks/Benchmarks/HTTPBenchmarks/HTTP1Benchmarks.swift:80-95`
- `Benchmarking/Benchmarks/Benchmarks/HTTPBenchmarks/HTTP2Benchmarks.swift:45-59`
- `Benchmarking/Benchmarks/Benchmarks/HTTPBenchmarks/HTTP3Benchmarks.swift:68-80`
- `Benchmarking/Bench/run.sh:43-46,199-200,316-334`
- `Sources/Examples/httpd-example/HTTPDExample.swift:65-83`

Why:

- The HTTP/1 response benchmark allocates and coalesces every response; production reuses a head buffer
  and sends the body separately.
- HTTP/2 and HTTP/3 response benchmarks mostly measure connection initialization and inbound decoding.
- The comparative harness reports best-of-N. Best-of-N selects favorable noise rather than estimating a
  distribution.
- `httpd-example` runs nine middleware layers even with quiet logging, while the competitor fixtures do
  not obviously perform equivalent work. That is a product-stack comparison, not a framework-floor
  comparison.

Change:

1. Add a warm, full HTTP/1 exchange benchmark using a persistent connection, existing input capacity,
   reused response capacity, actual router, and transport send fast path.
2. Split response serialization into:
   - cold allocating/coalescing;
   - warm `serializeHead(into:)`;
   - Content-Length already present/missing;
   - head-only and head+body scatter/gather.
3. Add steady-state HTTP/2 and HTTP/3 benchmarks that keep a connection alive and use monotonically
   increasing stream IDs.
4. Report median, interquartile range, and confidence/spread across rounds; randomize or interleave
   server order. Do not select the best result.
5. Maintain two macro suites:
   - bare framework floor with equivalent headers and no optional middleware;
   - realistic product stack with equivalent work on every server.

Proof:

- commit baselines for instructions, malloc count, CPU time, and RSS;
- run macro throughput/tail tests only on an idle, thermally stable host;
- use a separate load-generator machine for decision-grade saturation tests.

### P0 — Remove the per-connection 16 KiB scratch and copy

Locations:

- `Sources/Transport/HTTPTransport/POSIXKqueue/POSIXKqueueConnection.swift:34-41,77-152`
- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:332-351`
- `Sources/Core/HTTPCore/HTTPLimits.swift:143,172-173,204-215`

Why:

`readScratchNow` grows every connection's scratch to `maxLength` before calling `read`. For the normal
16 KiB request, every idle connection that attempts a read retains 16 KiB even if the socket returns
`EAGAIN`. `receive(into:)` then copies those bytes into the server buffer and takes a second scratch
lock.

The direct payload lower bounds are:

- default ceiling: `65,536 × 16,384 = 1 GiB`;
- high-throughput ceiling: `1,048,576 × 16,384 = 16 GiB`.

Change:

1. Make the readiness continuation report readiness only.
2. After resumption on the owning reactor, read directly into the caller's uninitialized tail using
   `Array.append(addingCapacity:initializingWith:)`/`OutputSpan`, committing only the count returned by
   `read`.
3. On `EAGAIN`, register readiness and retry; do not allocate `maxLength` persistent storage.
4. For the allocating `receive(maxLength:)` API, use
   `Array(unsafeUninitializedCapacity:)` and return only initialized bytes.
5. Remove the connection scratch `Mutex` entirely.

If the inout async API prevents a clean implementation, use one reusable 16 KiB scratch per reactor,
not per connection. That preserves the copy but reduces scratch storage from O(connections) to
O(reactors).

Proof:

- mallocs and instructions per H1 read;
- bytes copied per request;
- RSS delta at 1k, 10k, and 50k idle keep-alive connections;
- fragmented requests, EOF, `EINTR`, `EAGAIN`, cancellation, and fd-reuse race tests.

### P0 — Replace per-connection watchdog tasks with reactor timers

Locations:

- `Sources/Server/HTTPServer/HTTPServer+Timeout.swift:17-127`
- `Sources/Server/HTTPServer/HTTPServer.swift:219-270`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2.swift:108-134`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2Streaming.swift:91-128`

Why:

HTTP/1 creates a task group with a serve child and watchdog child per connection. Every read and send
arms/disarms a `Mutex`-protected deadline. HTTP/2 adds separate reader, send, and streaming-relay
deadlines. This is substantially better than a task group per read, but it scales task memory and
timer/scheduler work with connections rather than reactors.

Change:

- Give each reactor a timer wheel or deadline heap keyed by connection slot plus generation.
- Pass the nearest deadline to the reactor's `kevent` timeout.
- Arm/disarm by mutating loop-owned state.
- On expiry, validate the generation and close/reset the connection or stream.
- Start with a binary min-heap because it is simple; benchmark it against a hierarchical wheel at 10k,
  100k, and 1M scheduled deadlines. Adopt the wheel only if the measured connection count justifies it.

Proof:

- tasks/connection and RSS/connection;
- arm/disarm instructions;
- timeout precision and cancellation tests;
- churn benchmark with repeated re-arm/disarm;
- no stale timer may close a reused slot.

### P0 — Split reactor-safe handlers from general async handlers

Locations:

- `Sources/Server/HTTPServer/HTTPServer.swift:168-174`
- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:99-104`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2RequestStreaming.swift:37-65`

Why:

Apple's executor-preference semantics apply to the whole structured hierarchy. The current preference
therefore places request handlers and HTTP/2 child handler tasks on the connection's serial event loop.
That removes executor hops for trivial routes but makes CPU-heavy or blocking work a shard-wide
head-of-line blocker. Adding more connection tasks does not produce CPU parallelism when all of them
run on the same serial executor.

Change:

- Keep transport, parse, protocol, and serialization state on the owning reactor.
- Add an explicit reactor-safe handler shape: synchronous, nonblocking, bounded work, and unable to
  escape borrowed data.
- Dispatch ordinary async handlers to a configurable concurrent application executor. Make this the
  safe default.
- Carry execution policy in the compiled route plan, rather than dynamically guessing from runtime
  behavior.
- Return completed responses through a bounded per-reactor mailbox and batch completions.
- Do not create a detached task per request. Use structured tasks and a concurrency permit for HTTP/2
  and HTTP/3 streams.

Proof:

- pure trivial route, both inline and concurrent;
- 99% trivial + 1% 1 ms CPU work;
- 99% trivial + 1% 10 ms blocking work;
- unrelated-route p99 and p99.9 by reactor shard;
- executor-hop count and context-switch count;
- cancellation and shutdown while application work is in flight.

### P1 — Make kqueue state loop-owned and batch kernel changes

Locations:

- `Sources/Transport/HTTPTransport/POSIXKqueue/KqueueEventLoop.swift:35-57`
- `Sources/Transport/HTTPTransport/POSIXKqueue/KqueueEventLoop.swift:124-149`
- `Sources/Transport/HTTPTransport/POSIXKqueue/KqueueEventLoop.swift:174-231`
- `Sources/Transport/HTTPTransport/POSIXKqueue/KqueueEventLoop.swift:236-273`

Why:

- Read/write waiters live in `Mutex`-protected dictionaries of escaping closures.
- Event dispatch locks the registry and removes a dictionary entry.
- Each park performs a separate `kevent(... EV_ADD | EV_ONESHOT ...)` syscall.
- `drainInbox` copies the job and control arrays, then calls `removeAll(keepingCapacity:)` on the
  originals. Copy-on-write behavior needs measurement; a swap/double-buffer avoids ambiguity.
- The loop drains until the inbox is empty with no job budget, allowing job floods or a long synchronous
  job to delay readiness.
- Accept runs on the first data reactor, so connection churn steals time from that shard.
- Round-robin balances connection count, not active streams or queued work; one “elephant” HTTP/2
  connection can skew a shard.

Change:

1. Register accepted descriptors once and put a stable slot/generation token in `udata`.
2. Keep connection slots, read/write interest, and handlers in plain loop-owned storage.
3. Drain reads until `EAGAIN`; enable write interest only while output is blocked.
4. Accumulate changelist entries and submit them with the next event retrieval `kevent` call.
5. Replace closure dictionaries with indexed slots or a compact generation table.
6. Swap/double-buffer inbox batches instead of copying arrays; retain `Mutex` for the cross-thread MPSC
   boundary until a benchmark proves a lock-free queue is better.
7. Enforce per-turn I/O and job budgets, then repoll with timeout zero when work remains.
8. Benchmark a dedicated acceptor and power-of-two-choices shard selection using relaxed load counters.
9. Benchmark the long-lived `DispatchQueue` block against an explicitly owned `Thread`/pthread. Do not
   assume GCD guarantees core affinity.

Proof:

- syscalls/request and registry lock operations/request;
- reactor fairness under completion floods;
- 1, 2, 3, and 6 reactors on a dedicated host;
- many short connections and a mixed HTTP/1 + multiplexed HTTP/2 workload;
- no lost wakeup, duplicate resume, stale-fd callback, or shutdown drain regression.

### P1 — Add synchronous write/writev fast paths

Locations:

- `Sources/Transport/HTTPTransport/POSIXKqueue/POSIXKqueueConnection.swift:199-237`
- `Sources/Transport/HTTPTransport/POSIXKqueue/POSIXKqueueConnection.swift:354-458`
- `Sources/Transport/HTTPTransport/POSIXDispatch/OnceResumer.swift:22-69`

Why:

Every send enters `withUnsafeThrowingContinuation`, locks the cached resumer to install the
continuation, attempts the syscall, locks the resumer again to take it, and schedules the resumed task.
That work occurs even when the socket accepts the whole response synchronously. The scatter/gather loop
also creates a one- or two-element `[iovec]` on every attempt.

Change:

1. Attempt `write`/`writev` synchronously first.
2. Only create a continuation and install writable interest after `EAGAIN` or a partial write.
3. Build the vector with `withUnsafeTemporaryAllocation(of: iovec.self, capacity: 2)`.
4. Preserve owned array lifetimes in the parked path; use borrowed spans only in the immediate,
   nonsuspending path.
5. Apply the same shape to `sendfile`: attempt first, park only on would-block.

Proof:

- a socketpair benchmark with immediate writes and forced backpressure;
- mallocs, instructions, syscalls, and continuation resumes/send;
- partial head write, partial body write, `EINTR`, `EAGAIN`, cancellation, and peer-reset tests.

### P1 — Resolve and dispatch a route exactly once

Locations:

- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:378-405`
- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:99-104`
- `Sources/Server/HTTPServer/Routing/Router.swift:38-83,162-166`
- `Sources/Server/HTTPServer/Routing/Route.swift:136-165`
- `Sources/Server/HTTPServer/HTTPServer.swift:112-127`

Why:

The head must be resolved before buffering the body, which is correct. The returned `ResolvedRoute`
contains only metadata, so `Router.respond` later splits the path and scans the route table again.
`currentResolver` also obtains `currentResponder` under the hot-reload mutex; the responder is read
again before dispatch. Literal routes therefore pay two path arrays, two scans, and two responder
snapshot locks.

Change:

- Lower each immutable router generation into a dispatch structure:
  - exact `(method, path)` table for literal routes;
  - compact segment/radix trie for parameter and catch-all routes;
  - precomputed method/OPTIONS metadata.
- Return one immutable `DispatchPlan` at head time containing:
  - selected handler and execution policy;
  - body limit and streaming policy;
  - WebSocket metadata;
  - capture byte ranges;
  - the router generation/snapshot.
- Dispatch that exact plan after the body is framed. Never resolve against a newer hot-reload
  generation mid-request.
- Traverse the request target once over borrowed UTF-8. Do not allocate `[Substring]`.
- Store a small number of capture ranges inline using a deployable contiguous buffer/reserved capacity;
  materialize parameter strings/dictionaries only when the handler reads them.

Target complexity:

- literal lookup: expected O(1) by method/path key;
- parameter lookup: O(path bytes or segments), independent of unrelated route count;
- capture storage: O(number of captures), with no allocation for the common small case.

Proof:

- 1, 10, 100, 1,000, and 10,000 routes;
- first/middle/last hit and miss;
- literal, parameter, catch-all, HEAD fallback, OPTIONS, and 405;
- instructions and mallocs for head resolution plus dispatch, not each in isolation;
- hot reload between head and body completion.

### P1 — Stop copying response fields to synthesize Content-Length

Locations:

- `Sources/Protocols/HTTP1/ResponseSerializer.swift:64-99`
- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:126-153`
- `Sources/Server/HTTPServer/ServerResponse+Convenience.swift:13-19,50-58`

Why:

`serializeHead` copies the `HTTPFields` value and appends an interpolated Content-Length. When the
response fields have shared array storage, mutation triggers copy-on-write of the entire field array.
It also constructs and validates a decimal `String` just to emit ASCII bytes. Separately,
`.text("literal")` creates a body array and a content-type field collection for every request.

Change:

- Iterate the original fields directly.
- If framing is absent, append the literal `Content-Length: ` name and decimal digits directly to the
  reused output buffer.
- Inject `Alt-Svc` and other server-owned static fields at serialization time instead of copying and
  mutating the semantic response.
- Add `PreparedResponse`/static-response support that shares immutable body/header storage and allows an
  HTTP/1 wire head to be cached when it contains no request-specific fields.
- Precompute ETag and compressed variants for immutable static responses.

Proof:

- warm reused-buffer serializer with missing/present Content-Length;
- static text route through the full server path;
- mallocs/request must include convenience response construction;
- HEAD, 1xx, 204, 304, transfer-encoding, graceful drain, and Alt-Svc behavior.

### P1 — Bound the HTTP/2 mailbox and make flow control consumption-driven

Locations:

- `Sources/Server/HTTPServer/HTTPServer+HTTP2.swift:108-142,304-319`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2RequestStreaming.swift:13-16,62-102`
- `Sources/Core/HTTPCore/HTTPLimits.swift:97-117` in the current dirty tree

Why:

The merged HTTP/2 mailbox is explicitly `.unbounded`, and the streaming request body uses an
unbounded `AsyncStream`. Current `HTTPLimits` working-tree changes introduce inbound byte/chunk
watermarks, but the HTTP/2 runtime does not consume them yet. A slow consumer or reactor can therefore
turn network input into unbounded arrays and wakeup tickets. Besides being a correctness/security
defect, this expands the cache working set and allocator contention under load.

Change:

- Replace payload-carrying `AsyncStream` with a byte- and chunk-bounded channel.
- Stop the reader at the high watermark so TCP flow control supplies backpressure.
- Replenish HTTP/2 stream and connection receive windows when the application consumes data, not merely
  when DATA arrives.
- Coalesce wakeup tickets and batch several inbound chunks per consumer turn.
- Bound concurrent handler tasks by the negotiated/enforced stream limit and an application permit.

Proof:

- peer sends faster than a streaming handler consumes;
- bounded RSS and queued bytes;
- no frame loss or reorder;
- fair progress for unrelated streams;
- WINDOW_UPDATE conformance and slow-consumer throughput.

### P2 — Remove HTTP/2 frame/event/buffer churn

Locations:

- `Sources/Protocols/HTTP2/HTTP2FrameDecoder.swift:14-56`
- `Sources/Protocols/HTTP2/HTTP2Connection.swift:220-286`
- `Sources/Protocols/HTTP2/HTTP2FrameWriter.swift:13-21`
- `Sources/Protocols/HTTP2/HTTP2Connection+Response.swift:176-187`
- `Sources/Protocols/HTTP2/HTTP2Connection+FlowControl.swift:184-231`
- `Sources/Protocols/HTTP2/HTTP2Connection.swift:61-99,143,368-370`

Why:

- Every frame payload becomes a new `[UInt8]`, measured at one malloc/frame.
- `receive` accumulates into one array, builds a frame array, and shifts consumed input with
  `removeFirst`.
- The writer swaps its output with an empty array. This avoids a copy but discards reusable capacity
  from the engine until the caller returns it.
- Each response reserves a new 512-byte HPACK buffer before copying it into the frame writer.
- Connection WINDOW_UPDATE builds, compacts, and sorts a ready-stream array.
- `StreamRecord` is a large dictionary value containing hot flow-control fields plus cold request/body
  arrays. Remove/reinsert moves that value repeatedly.
- The closed-stream FIFO uses `removeFirst`.

Change:

1. Decode a borrowed `FrameView` over an owned input/ring buffer and process frames before advancing the
   cursor. Copy only data that must outlive the receive turn.
2. Process events incrementally or into caller-provided storage instead of returning a fresh event array.
3. Encode HPACK directly into the final writer: reserve nine frame-header bytes, encode the block, then
   backpatch the length/header.
4. Return drained output capacity to the connection after `send` completes, or use two reusable output
   buffers.
5. Split stream state into a compact hot record and separately allocated cold body/request state; measure
   a dense slot/slab keyed by stream ID against the dictionary.
6. Maintain eight urgency ready queues with membership bits instead of compacting and sorting on each
   connection WINDOW_UPDATE.
7. Make the recently closed stream order a ring buffer.

Proof:

- steady-state 1/32/128 active streams;
- frame floods, DATA-heavy responses, and window-constrained responses;
- mallocs/frame, mallocs/request, bytes copied, cache misses, and RSS/stream;
- priority/fairness, reset, flow-control, and HPACK state tests.

### P2 — Narrow HTTP/3 actor ownership and eliminate stream-buffer shifts

Locations:

- `Sources/Server/HTTPServer/HTTPServer+HTTP3.swift:20-103,175-292`
- `Sources/Protocols/HTTP3/HTTP3Connection+Streams.swift:243-262`
- `Sources/Protocols/HTTP3/HTTP3Connection.swift:234-245`
- `Sources/Protocols/HTTP3/HTTP3Connection+Response.swift:20-34,65-121`

Why:

Every stream task hops through one connection actor for receive and response encoding. QPACK and
connection control genuinely require ordering, but per-stream frame parsing and DATA handling do not.
Frame payloads are copied, consumed stream buffers are shifted with `removeFirst`, actions are
materialized and drained as arrays, and dynamic response encoding materializes a whole
`[HeaderField]`.

The streaming response path already frames DATA off actor, which is the right direction.

Change:

- Keep per-stream frame/parser/body state in the stream task.
- Keep only QPACK dynamic state, critical-stream state, SETTINGS, and connection-close state in the
  actor/single owner.
- Use cursor/ring buffers and borrowed frame views per stream.
- Batch actor interactions for a complete HEADERS section rather than every body chunk.
- Return direct send commands to the current stream where possible; reserve role-addressed actions for
  control/QPACK streams.
- Reuse action/output buffers and encode response fields into final storage.

Network.framework remains a separate performance boundary for TLS/QUIC. Benchmark its copies, task
hops, and maximum throughput independently from the sans-I/O HTTP/3 engine before changing engine code
to compensate for transport overhead.

Proof:

- 1/32/128 concurrent QUIC request streams;
- body-heavy streams plus independent small requests;
- actor hops, allocations, and bytes copied per request;
- QPACK blocking/unblocking and control-stream conformance;
- end-to-end HTTP/3 on a remote load generator.

### P2 — Reduce request materialization and repeated header scans

Locations:

- `Sources/Protocols/HTTP1/RequestLineParser.swift:24-46`
- `Sources/Protocols/HTTP1/HeaderParser.swift:27-101`
- `Sources/Core/HTTPCore/HTTPFieldName.swift:61-160`
- `Sources/Core/HTTPCore/HTTPFields.swift:36-74`

Why:

- HTTP/1 materializes a method string even for common methods.
- A mixed-case parsed field name stores the original string and a canonical lowercase string.
- Security checks correctly validate field lines, but the line is scanned for CR, LF, colon, field-name
  token, and field-value validity in separate passes.
- `HTTPFields` is correctly array-backed for small ordered header sets, but high-frequency fields can be
  scanned repeatedly for count, value, framing, host, request ID, and middleware.

Change:

- Compare known method byte sequences and return static method constants; materialize only custom
  methods.
- Intern registered field names from bytes while preserving raw spelling where the public API requires
  it.
- Keep the ordered field vector, but benchmark a compact registered-field presence/count/first-index
  side index for the handful of hot fields.
- Consider a fused field-line validation pass only if instruction profiling confirms those scans are
  material. Do not weaken CRLF, token, field-value, size, or smuggling validation.

Proof:

- realistic 10/20/50-field requests;
- lower-case, conventional mixed-case, custom long names, repeats, and malformed input;
- instructions, mallocs, branch misses, and bytes scanned;
- all existing parser/security tests and fuzzers.

### P2 — Compile middleware and provide prepared variants

Locations:

- `Sources/Server/HTTPServer/Middleware/HTTPResponder+Middleware.swift:15-52`
- `Sources/Server/HTTPServer/Middleware/MiddlewareChain.swift:19-49`
- `Sources/Server/HTTPServer/Routing/Route.swift:55-76,168-181`
- `Sources/Examples/httpd-example/HTTPDExample.swift:65-83`

Why:

The chain is composed once, which avoids build-time work per request, but every layer remains an
existential async witness call. That limits specialization and adds ARC/executor bookkeeping. Static
responses also recompute conditional/compression work that can be prepared once.

Change:

- Add benchmarks for 0/1/5/10 no-op layers and the real chain.
- Offer a generic/result-builder path that can specialize/fuse a fixed chain.
- Preserve the heterogeneous existential array as the dynamic configuration path.
- Where generic fusion is impractical, compile the chain once into one `@Sendable` closure and measure
  it against nested existential responders.
- Precompute ETag and compressed variants for prepared immutable responses; keep streaming/dynamic
  compression separate.

Proof:

- instructions, retains/releases, mallocs, and RPS by layer count;
- correct request/response order and short-circuit behavior;
- equivalent middleware work in comparative benchmarks.

### P3 — Improve admission and connection distribution

Locations:

- `Sources/Transport/HTTPTransport/POSIXKqueue/POSIXKqueueTransport.swift:145-239`
- `Sources/Transport/HTTPTransport/POSIXShared/POSIXSocket.swift:209-245`
- `Sources/Server/HTTPServer/HTTPServer.swift:82-99,143-187`

Why:

The transport yields every accepted connection into an unbounded `AsyncStream`; the server creates a
task-group child before admission, then locks a global string-keyed per-host dictionary. Peer address
formatting allocates two maximum-sized C-char arrays, maps a prefix into another byte array, constructs
strings, and parses the port. These costs are per connection rather than per request, but they dominate
connection-churn workloads and allow rejected peers to consume task/handoff work first.

Change:

- Move global admission before connection-task creation.
- Store the binary peer address as the accounting key and format it lazily for logs/public metadata.
- Use a relaxed atomic total plus an exact sharded per-host table; preserve the cap invariant
  transactionally.
- Bound the accepted-connection handoff.
- Benchmark a dedicated acceptor and load-aware shard assignment.

Proof:

- accepted/rejected connections per second;
- allocations and task creations/connection;
- exact global and per-host cap under races;
- IPv4, IPv6, Unix socket, shutdown, and fd-exhaustion behavior.

## Work that should not be prioritized

- Do not replace every `Mutex` with atomics. Loop-owned state is better than either; the remaining
  cross-thread queue should use the simplest primitive that wins a benchmark.
- Do not add `Task.detached` per request or stream. It defeats structured cancellation and increases
  scheduler traffic.
- Do not use an actor per HTTP/1 connection merely to remove locks. The reactor already provides
  single ownership with lower hop overhead.
- Do not raise deployment targets for `InlineArray`.
- Do not promise zero-copy across an arbitrary suspending handler. Borrowed spans cannot safely escape
  their owner; copy/retain at the async boundary or provide a synchronous borrowed handler API.
- Do not reintroduce recursive parsers.
- Do not revisit the previously rejected SWAR `memchr` replacement or HPACK dynamic-table hash index
  without a changed workload and a new benchmark. Prior project audits measured those ideas slower on
  the relevant short-input/small-table shapes.
- Do not use best-of-N benchmark reporting.

## Benchmark and profiling program

### Microbenchmarks to add

1. `server/h1/full-exchange-steady`
2. `transport/kqueue/read-direct` and `read-parked`
3. `transport/kqueue/write-immediate`, `writev-immediate`, and forced-backpressure variants
4. `server/deadline/arm-disarm` and `reactor/timer-expire`
5. `router/dispatch` across route cardinality and pattern shape
6. `middleware/noop-N` and `middleware/realistic`
7. `http2/connection/steady-request-response-N-streams`
8. `http2/frame-view` versus copied frame
9. `http3/connection/steady-request-response-N-streams`
10. `server/prepared-response` versus convenience response construction

Every microbenchmark should report instructions, malloc count/bytes, CPU time, and retain/release
traffic. Wall time is secondary on a noisy workstation.

### End-to-end matrix

Protocols:

- HTTP/1.1 cleartext and TLS;
- HTTP/2 TLS and h2c where relevant;
- HTTP/3.

Payloads:

- static empty/tiny text;
- realistic 12-header request;
- JSON encode;
- 1 KiB and 64 KiB bodies;
- upload/echo;
- streaming upload and response;
- cached/prepared response.

Concurrency:

- 1, 64, 256 active connections;
- 10k+ idle keep-alives;
- 1/32/128 streams per multiplexed connection;
- mixed slow-handler workload.

Load:

- closed-loop saturation to find capacity;
- open-loop at 50%, 70%, 85%, and 95% of measured capacity to expose queueing;
- sufficient duration to observe p99.9 without relying on a handful of samples.

Metrics:

- successful RPS and errors;
- p50/p95/p99/p99.9/max without coordinated omission;
- CPU%, instructions/request, context switches, syscalls/request;
- mallocs and allocated bytes/request;
- RSS/idle connection and RSS/active stream;
- task count, executor hops, reactor queue depth;
- bytes copied/request and output backlog;
- fairness by route, connection, and stream.

Tools:

- Ordo package-benchmark for deterministic microbenchmarks;
- Instruments Time Profiler and Allocations;
- Swift Concurrency instrument for tasks/hops;
- System Trace for syscalls, wakeups, and context switches;
- a separate load generator over a physical interface for production claims.

## Execution order and promotion gates

### Phase 0 — Truthful baselines

- repair benchmark parity and statistics;
- commit the warm full-exchange baselines;
- add mixed-workload and idle-connection memory tests.

### Phase 1 — Low-risk hot-path removal

- direct receive into the destination buffer;
- immediate write/writev fast path and stack `iovec`;
- direct Content-Length serialization;
- prepared static responses.

### Phase 2 — One dispatch plan

- immutable responder/router snapshot;
- compiled literal/trie router;
- route once at head time and dispatch the same plan.

### Phase 3 — Reactor ownership

- reactor timer structure;
- loop-owned fd/handler state;
- batched kqueue changelists;
- fairness budget, dedicated acceptor, and load-aware shard assignment;
- hybrid inline/application execution.

### Phase 4 — Multiplexed protocols

- bounded HTTP/2 intake and consumption-driven receive windows;
- borrowed frame views/cursors;
- reusable output buffers;
- compact stream state and ready queues;
- narrow HTTP/3 actor ownership.

### Phase 5 — Middleware and advanced response preparation

- specialized/fused fixed chains;
- precompressed/static validators;
- realistic parity retest against reference servers.

For every phase:

1. capture before/after instruction, allocation, CPU, RSS, and macro results;
2. run all protocol/concurrency/security tests;
3. add a permanent regression test for every bug exposed;
4. retain the change only if the intended metric improves without a correctness, memory, or tail
   regression;
5. revert complicated machinery whose gain is within benchmark noise.

## State-of-the-art completion criteria

The implementation should not be called state of the art until all of these are true:

- a warm HTTP/1 request has no per-request framework allocation for a prepared static route except the
  ownership boundary explicitly required by the public API;
- immediate writes do not create a continuation or heap-backed `iovec`;
- idle timeout memory and timer work scale with reactors, not connections;
- application CPU/blocking work cannot stall an I/O reactor;
- route cost is independent of unrelated literal-route count and resolution occurs once;
- HTTP/2 and HTTP/3 input is bounded and applies protocol flow control at consumption;
- frame decoding does not allocate one payload array per frame when the payload can be consumed in the
  same turn;
- steady-state HTTP/2/3 benchmarks reuse connections and exercise real stream concurrency;
- performance claims come from median/spread and open-loop tail measurements on a qualified host;
- security limits, cancellation, fairness, and graceful shutdown remain correct under adversarial load.
