# Codebase review — 2026-07-31

## Outcome

The package has a broad, tested HTTP/1.1, HTTP/2, HTTP/3, WebSocket, routing, and
middleware implementation, but it is not production-complete for the stated
high-throughput goal. The highest-risk gaps are loss or unbounded buffering at
transport/application boundaries, incomplete HTTP/2 reset cancellation, work
running on serial I/O executors, admission after task creation, and several
security-boundary bugs.

This was a review, not an authorization to redesign those subsystems. No
production source was changed. The recommended execution order is at the end of
this document.

## Scope and gate

- Reviewed 558 Swift files / 58,528 lines: 330 source files / 33,668 lines and
  228 test files / 24,860 lines. Vendored BoringSSL implementation details were
  excluded.
- `swift-tools-version` is 6.4 and the package enables Swift 6 language mode.
- The actual deployment floor in `Package.swift` is macOS 15.0 and iOS 18.0.
  This is the compatibility gate, even though `CLAUDE.md` says macOS 15.6.
- Apple documentation was checked for the APIs central to the recommendations.
  `Span`, `RawSpan`, `MutableSpan`, `OutputSpan`, `Synchronization.Mutex`, and
  `Synchronization.Atomic` are available at this package's deployment floor.
  `Span` values remain scoped borrows; bytes that cross an `await` still require
  ownership or an explicitly managed lifetime.
- Apple executor semantics also confirm that
  `withTaskExecutorPreference` moves the operation and its task hierarchy to
  the preferred executor whenever possible. This matters for the reactor
  starvation finding below.

## Verification performed

- `HTTP_WARNINGS_AS_ERRORS=1 swift test --parallel` — passed.
- `swift build --target HTTPCore -Xswiftc -strict-memory-safety` — passed with
  numerous strict-memory-safety diagnostics in pointer-backed parsing,
  validation, date formatting, and Huffman decoding. The package does not
  enable `.strictMemorySafety()` and ADR 0002 explicitly defers adoption.
- `swiftlint lint --strict --quiet` — failed:
  - `Sources/Server/HTTPServer/HTTPServer+HTTP2.swift:55`: cyclomatic complexity
    29, configured maximum 12.
  - `Sources/Server/HTTPServer/HTTPServer+HTTP2.swift:122`: closure body 134
    lines, configured maximum 60.
  - `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:538`: file 407
    lines, configured maximum 400.
- `swift format lint --strict --recursive Sources Tests Package.swift` — failed
  with 22 formatting violations. Because CI runs strict lint and format, the
  current main branch is expected to be CI-red despite the test suite passing.
- Restored generated analysis reports:
  - arcleak: 330 files, zero reported findings.
  - deadwood: 558 files, nine reported candidates.
  - dolly: 330 files, 182 clone groups.
  These are supporting signals, not proofs. In particular, arcleak did not find
  the manual response-cache retain cycle described below.
- Restored benchmark results are historical artifacts from June 2026, not
  measurements of the current commit. They cannot substantiate a current
  throughput or regression claim. No committed `.benchmarkBaselines` gate was
  found.

## Priority findings

### P0 — correctness, security, or unbounded resource use

#### 1. HTTP/1 WebSocket input can be silently discarded

Locations:

- `Sources/Server/HTTPServer/HTTPServer+WebSocket.swift:103`
- `Sources/Server/HTTPServer/HTTPServer+WebSocket.swift:119`
- `Sources/Server/HTTPServer/HTTPServer+WebSocket.swift:123`
- `Sources/Server/HTTPServer/HTTPServer+WebSocket.swift:154`

The merged inbound/broadcast mailbox uses
`AsyncStream(bufferingPolicy: .bufferingNewest(256))`. The socket reader and hub
both yield into it while the only consumer can suspend in the application
handler or socket send. On overflow, the oldest entries are discarded and the
result of `yield` is ignored. Discarding an inbound TCP byte chunk can corrupt
WebSocket framing, not merely drop one application message. A count of chunks
also does not bound retained bytes.

Change: split transport input from broadcast delivery. Transport bytes need a
lossless, byte-watermarked, backpressured handoff. Broadcast delivery may have
an explicit bounded drop/disconnect policy, but it must inspect every yield
result.

Regression: block handler/output progress, feed more than 256 ordered inbound
chunks, and prove byte-for-byte delivery or an intentional connection close
without parser corruption.

#### 2. HTTP/2 WebSocket tunnel buffering is unbounded

Locations:

- `Sources/Server/HTTPServer/HTTPServer+WebSocket.swift:230`
- `Sources/Server/HTTPServer/HTTPServer+WebSocket.swift:295`
- `Sources/Server/HTTP2/HTTP2Connection+FlowControl.swift:48`

The tunnel signal stream is `.unbounded`. The engine replenishes tunnel flow
control on receipt and deliberately applies no request-body bound, while the
consumer may suspend in handler work. A conforming peer can therefore grow
memory without bound.

Change: tie WINDOW_UPDATE to application consumption and introduce per-stream
and per-connection byte watermarks. A slow consumer must backpressure the peer
or cause a documented reset/close.

#### 3. The HTTP/2 connection's raw input mailbox is unbounded

Locations:

- `Sources/Server/HTTPServer/HTTPServer+HTTP2.swift:108`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2.swift:300`

A dedicated reader continually receives and yields raw chunks into an unbounded
stream. Its sole consumer also performs protocol and application-related work.
An adversarial peer can outpace that consumer, especially when sending invalid
or flow-control-exempt traffic.

Change: use a lossless byte-bounded channel. Suspending the reader at its high
watermark should naturally backpressure the kernel. A drop policy is not valid
for transport bytes.

#### 4. HTTP/2 request streaming is not consumption-gated

Locations:

- `Sources/Server/HTTPServer/HTTPServer+HTTP2RequestStreaming.swift:13`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2RequestStreaming.swift:92`
- `Sources/Server/HTTP2/HTTP2Connection+FlowControl.swift:93`
- `Sources/Core/HTTPCore/HTTPLimits.swift:133`

Each streaming request has an unbounded `AsyncStream`. HTTP/2 receive windows
are replenished when data arrives, not when the handler consumes it. The only
meaningful cap is the route body limit. At the default 1 GiB body limit and 128
concurrent streams, a single connection has a theoretical 128 GiB application
buffering envelope before overhead.

Change: record consumption, aggregate it on the connection owner, and emit
WINDOW_UPDATE only below stream and connection byte watermarks. Keep one owner
for connection state; atomics are appropriate only for independent counters,
with the weakest correct ordering.

Regression: use a non-consuming and a deliberately slow handler while a peer
sends across many streams; assert stable memory, bounded windows, sibling
progress, and cancellation.

#### 5. HTTP/1 “streaming” retains and copies whole bodies

Locations:

- `Sources/Server/HTTPServer/HTTPServer+RequestStreaming.swift:62`
- `Sources/Server/HTTPServer/HTTPServer+RequestStreaming.swift:91`
- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:30`

Content-length bodies are first accumulated in the persistent connection
buffer, then copied into arrays for yielded chunks. Chunked bodies retain the
wire buffer, accumulate the complete decoded body, and create yielded copies.
After completion, `removeAll(keepingCapacity: true)` preserves a large peak
allocation for the keep-alive connection. The result is O(body size) retained
memory and can reach two or three live copies, rather than bounded streaming.

Change: compact incrementally into a fixed receive window and transfer one
owned chunk at a time. The chunk decoder must emit rather than accumulate.
Borrowed spans can remove copies inside a synchronous parser call, but cannot
escape across handler `await` points; ownership transfer is the correct
asynchronous boundary.

Regression/measurement: stream a 256 MiB upload over keep-alive, then a tiny
request, and assert bounded RSS, allocation count, and retained capacity.

#### 6. `RST_STREAM` does not finish HTTP/2 request streams

Locations:

- `Sources/Server/HTTPServer/HTTPServer+HTTP2RequestStreaming.swift:44`
- `Sources/Server/HTTP2/HTTP2Connection+ControlFrames.swift:88`

`streamReset` falls through to tunnel handling, which only removes WebSocket
tunnels. An active request-body stream is neither removed nor finished.
Handlers waiting on the body can remain parked until the entire connection
closes, and request accounting remains outstanding. Buffered and streaming
handler work also lacks a general per-stream cancellation handle, amplifying
Rapid Reset-style wasted work.

Change: make reset a first-class transition that removes and finishes the body
stream and cancels handler/relay work. Keep an explicit per-stream task or
cancellation record owned by the connection.

Regression: reset mid-body, verify the handler exits and accounting returns to
zero while a sibling stream completes normally.

#### 7. Application handlers run on serial I/O executors

Locations:

- `Sources/Server/HTTPServer/HTTPServer.swift:168`
- `Sources/Transport/HTTPTransport/KqueueEventLoop.swift:5`

The entire connection-serving operation is wrapped in the transport's preferred
executor. Kqueue documents read → parse → route → respond → write inline on one
serial event-loop thread. CPU-heavy or blocking user work can therefore stall
every connection assigned to that reactor. This maximizes neither parallel
request capacity nor tail-latency isolation.

Change: keep readiness, parsing, protocol state, and socket I/O on the owning
reactor; run application handlers and their child tasks on a configurable
concurrent executor, then return the response to the owner for ordered writes.
Do not add a lock around protocol state. Actor isolation or single-owner reactor
state remains preferable there.

Measurement: compare trivial, CPU-heavy, and blocking routes under mixed load.
Report throughput, p50/p95/p99, reactor utilization, context switches, and
allocations before choosing an inline fast-path policy.

#### 8. Connection admission occurs after unbounded queuing and task creation

Locations:

- `Sources/Transport/HTTPTransport/KqueueEventLoop.swift:100`
- `Sources/Transport/HTTPTransport/EpollEventLoop.swift:104`
- `Sources/Transport/HTTPTransport/NetworkFrameworkTransport.swift:76`
- `Sources/Server/HTTPServer/HTTPServer.swift:86`
- `Sources/Server/HTTPServer/HTTPServer.swift:150`

Accept streams are unbounded. The server creates a task-group child for each
dequeued connection, and only then applies global/per-host admission. Under an
accept flood or executor starvation, queued connections and tasks can grow
before the nominal connection limit is counted.

Change: perform synchronous admission before child-task creation, include
queued/handshaking connections in the hard cap, close rejects immediately, and
stop rearming or backpressure the accept source at capacity.

#### 9. “Bounded” rate-limit and session maps can exceed their caps

Locations:

- `Sources/Middleware/HTTPMiddleware/RateLimitMiddleware.swift:74`
- `Sources/Middleware/HTTPSession/InMemorySessionStore.swift:62`

Both implementations prune expired entries when the map is full and then
insert unconditionally. If every entry is live, repeated unique keys grow the
maps indefinitely.

Change: after pruning, either reject/fail closed or evict by a deterministic
bounded policy. A fixed-size sharded cache avoids a single global hot lock.
Rate limiting should prefer a 429/rejection over allocating for attacker-chosen
new identities.

Regression: fill the map with live entries, submit `maximum + 1` unique entries,
then repeat under concurrent churn and assert the hard bound.

#### 10. The default rate-limit identity is Host, not client

Location: `Sources/Middleware/HTTPMiddleware/RateLimitMiddleware.swift:41`

The default key is `HTTPRequest.effectiveAuthority`. That is typically shared
by all legitimate clients and is attacker-controlled through Host/:authority.
One client can consume every user's budget, while randomized authorities evade
the limit and exercise the unbounded-map bug. The customization closure cannot
see `RequestContext`, so it cannot safely default to the verified peer address.

Change: accept `(HTTPRequest, RequestContext) -> ClientKey` and default to the
transport peer address. Honor forwarded addresses only behind explicit trusted
proxy CIDRs.

#### 11. File serving has a symlink-check/open race

Locations:

- `Sources/Middleware/HTTPFileServing/FileResponder.swift:188`
- `Sources/Middleware/HTTPFileServing/FileResponder.swift:217`
- `Sources/Middleware/HTTPFileServing/FileResponder.swift:283`

The responder resolves symlinks, checks containment, and later classifies and
opens by pathname. A writer can swap a path component after validation and
before open, escaping the root.

Change: open the root directory once and traverse components with
`openat`/`fstatat` and `O_NOFOLLOW`, then serve from the same verified file
descriptor. Isolate POSIX calls behind a small safe wrapper with documented
descriptor and path invariants.

Regression: repeatedly swap a symlink between an allowed file and an outside
secret while concurrently requesting it; no outside bytes may be returned.

#### 12. Hot reload can combine old policy with a new handler

Locations:

- `Sources/Server/HTTPServer/HTTPServer.swift:102`
- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:100`
- `Sources/Server/HTTPServer/HTTPServer+RequestReader.swift:391`
- `Sources/Server/HTTPServer/HTTPServer+HTTP2.swift:62`
- `Sources/Server/HTTPServer/HTTPServer+HTTP3.swift:125`

The mutex stores only the responder and separate helpers reread it. A request
can resolve body policy/streaming/WebSocket metadata from one generation, then
dispatch to a newer responder. This violates the documented in-flight snapshot
semantics and can apply an old permissive body limit to a newly restrictive
route.

Change: store one immutable `ResponderSnapshot` containing responder, resolver,
and generation. Capture it once when request headers complete. Prefer a single
route match returning an immutable dispatch plan containing handler, metadata,
and parameters.

Regression: reload between header parsing, body receipt, and dispatch for
HTTP/1, HTTP/2, and HTTP/3; each request must observe exactly one generation.

#### 13. JWT middleware preserves a spoofed trusted identity header

Location: `Sources/Auth/HTTPAuth/JWTMiddleware.swift:60`

The middleware overwrites `X-Auth-Subject` only when a valid token contains a
`sub` claim. With a valid token lacking `sub`, a client-supplied
`X-Auth-Subject` survives and can be mistaken downstream for server-asserted
identity.

Change: remove all trusted identity assertion headers before authentication,
then add only server-derived values. Consider requiring `sub` by default, with
an explicit opt-out.

Regression: submit a valid no-subject token and a spoofed identity header; the
downstream request must not contain the spoofed value.

### P1 — memory integrity and bounded concurrency

#### 14. Response-cache nodes form retain cycles and cost accounting is low

Locations:

- `Sources/Middleware/HTTPCaching/ResponseCache.swift:47`
- `Sources/Middleware/HTTPCaching/ResponseCache.swift:111`
- `Sources/Middleware/HTTPCaching/CacheMiddleware.swift:26`
- `Sources/Middleware/HTTPCaching/CacheMiddleware.swift:137`

Each node strongly owns both `prev` and `next`, forming cycles that survive
cache deallocation or hot replacement. Cache cost counts roughly body + 256,
but omits key, response headers, Vary metadata and values, node, and dictionary
overhead, so the advertised byte bound can be exceeded substantially.
`freshFor + staleWindow` can also overflow and trap for large but parseable
delta-seconds.

Stale revalidation uses unstructured tasks with no global concurrency bound or
deadline. Many distinct stale keys can create many stuck tasks.

Change: make the predecessor weak or explicitly break links; use conservative,
tested byte cost; use reporting/saturating duration arithmetic; and run stale
revalidation through an injected, bounded supervisor with deadline and
cancellation. This extra synchronization belongs only on the cold stale path.

#### 15. Default limits are too permissive for the current buffering model

Location: `Sources/Core/HTTPCore/HTTPLimits.swift:133`

Defaults include a 1 GiB body/WebSocket limit, 65,536 connections, and 1,024
connections per host. Public initialization also permits incoherent negative or
zero values. Those limits combine dangerously with the unbounded/non-streaming
paths above.

Change: make illegal configurations unrepresentable with validated byte/count/
duration types or a throwing initializer. Use bounded production defaults and
require explicit opt-in for very high ceilings. Do not use lower defaults as a
substitute for actual backpressure.

#### 16. WebSocket hub is one global actor and has unbounded cardinality

Location: `Sources/WebSocket/HTTPWebSocket/WebSocketHub.swift:15`

Every topic, subscription, publication, and removal serializes through one
actor. Removal scans every topic and allocates a key array. Topic/subscription
cardinality is unbounded.

Change: shard by topic using `Synchronization.Mutex` or topic owners, keep a
reverse subscription index for proportional removal, snapshot sinks under the
lock, and deliver outside it. Bound attacker-controlled topic/subscription
cardinality.

#### 17. Timeout middleware is cooperative, not a hard response deadline

Location: `Sources/Middleware/HTTPMiddleware/TimeoutMiddleware.swift:46`

The losing responder task is cancelled, but a task-group scope cannot return
until that child exits. A blocking or cancellation-ignorant handler can delay
the 504 indefinitely. This is not itself fixable by adding more task-group
logic.

Change: document the contract precisely, propagate request deadlines, and keep
application work off the reactor. Hard isolation for hostile code requires a
separate process boundary, not a Swift task.

### P2 — measured hot-path improvements

#### 18. HTTP/2 and HTTP/3 frame decoding copies every payload

Locations:

- `Sources/Protocol/HTTP2/HTTP2FrameDecoder.swift:54`
- `Sources/Server/HTTP2/HTTP2Connection.swift:271`
- `Sources/Protocol/HTTP3/HTTP3FrameDecoder.swift:65`
- `Sources/Server/HTTP3/HTTP3Connection+Streams.swift:242`

Decoders materialize payload arrays, connection code materializes frame arrays,
and input buffers use front removal/compaction. DATA is then copied again into
events. This creates allocations and memory movement on the request hot path.

Change: add an internal synchronous borrowed `RawSpan` frame walk and
immediately process frames on the connection owner. Materialize only payloads
that must escape the borrow. Keep the public owning decoder API for callers.
Use a sliding cursor with periodic compaction rather than removing every
prefix.

Measurement: allocations/request, copied bytes, instructions, and throughput
across mixed control/DATA frame sizes. No change should land on an assumed
zero-copy win.

#### 19. Router matching is linear, allocating, and repeated

Location: `Sources/Routing/HTTPRouting/Router.swift:47`

Resolution splits paths and linearly scans routes. Dispatch can match again, and
captures construct dictionaries and joined strings. Complexity is O(routes ×
segments) per match and allocations scale with route/capture count.

Change: first make resolution return the immutable dispatch plan described in
finding 12 so each request matches once. Benchmark 10/100/1,000 route
worst-cases; only then consider a compiled immutable radix tree/trie.

#### 20. Authentication/session crypto has avoidable allocation and weak key APIs

Locations:

- `Sources/Core/HTTPCore/HMACSHA256.swift:19`
- `Sources/Core/HTTPCore/SHA256.swift:14`
- `Sources/Auth/HTTPAuth/BasicAuthMiddleware.swift:82`
- `Sources/Auth/HTTPAuth/JWT.swift`
- `Sources/Middleware/HTTPSession/SessionMiddleware.swift`

The in-house SHA/HMAC path creates pad arrays, concatenations, and a padded
whole-message copy. Basic fixed credentials create ephemeral symmetric keys and
recompute blinded comparisons per request. Session and HS256 APIs accept weak
or empty key material without a fail-closed length contract.

Change: prefer the already-used first-party `swift-crypto` implementation at
security boundaries, or isolate a fixed-buffer/incremental primitive if package
layering prevents that and prove it against test vectors. Require adequate key
material and support rotation. Precompute fixed credential tags with one
per-instance blinding key. Benchmark before retaining any custom crypto for
performance.

Request/session IDs also concatenate two unpadded radix strings. The result is
not fixed-width and the concatenation is not an injective representation of the
two values. Encode 16 random bytes or zero-pad each 64-bit component.

## Feature-completion and operational gaps

- HTTP/3 CI remains advisory and current `h3spec` integration reports 48 of 49
  failures due to a transport-expectation mismatch. It is not a conformance
  gate.
- HTTP/3 load testing is advisory; Linux HTTP/3 remains intentionally absent.
- ~~Streaming response compression is explicitly unimplemented in
  `Sources/Middleware/HTTPCompression/CompressionMiddleware.swift:71`.~~
  **Implemented.** A streamed body is coded incrementally through a
  `CompressingBodyWriter` over the `StreamingContentEncoder` /
  `ContentEncoderStream` seam; `Content-Length` is dropped and h1 frames it
  chunked. gzip and Brotli stream on Darwin; the `CZlibCoding`, `CBrotli` and
  `CZstd` shims are one-shot only, so those builds fall through to identity
  rather than buffering the body to code it.
- Strict Memory Safety remains deferred. Unsafe regions should be isolated,
  marked with explicit invariants, and tested before enabling the package trait
  as a gate.
- `Package.swift` depends on `ADFoundation` via mutable `branch: "main"` and
  the root `Package.resolved` is ignored. Builds are not reproducible. Pin a
  release or exact reviewed revision, automate updates, and generate dependency
  review/SBOM output.
- There is no committed benchmark-regression baseline, so CI executes a harness
  without enforcing drift. Establish hardware-specific baselines and compare
  statistically stable distributions rather than a single RPS number.
- The restored June results include runs below the stated 200k RPS goal; they
  are from different harness/configuration states and must not be compared
  directly with one another or presented as current results.
- Documentation is materially stale:
  - `docs/Security.md` still describes accept backoff as pending.
  - `docs/standards/README.md` and `docs/standards/CONFORMANCE.md` still describe
    HTTP/3, QPACK, WebSocket, priority, and Autobahn states that conflict with
    code and CI.
  - body-stream and decompression comments still describe capabilities as
    reserved or memory-bounded when current implementations contradict them.
- Deadwood marks `HTTPServer+Streaming.swift:85 bufferedResponse(_:)` as an
  unused production candidate. Other reported test tags may be intentional
  public test API and should not be deleted blindly.
- The 182 clone groups include generated tables and protocol symmetry. Deduplicate
  only where it improves invariant ownership without introducing abstraction
  overhead on a measured hot path.

## Proposed execution plan

Every performance claim below requires a before/after benchmark on the same
hardware and toolchain. Every bug fix requires a permanent regression test.

### Phase 0 — stop loss, spoofing, races, and unbounded growth

1. Introduce lossless byte-watermarked transport/application handoffs for
   HTTP/1 WebSocket and HTTP/2 raw input.
2. Make HTTP/2 body and tunnel flow control consumption-gated with stream and
   connection bounds.
3. Implement HTTP/2 reset cancellation and stream cleanup.
4. Enforce hard rate-limit/session capacities and derive rate identities from
   verified peer context.
5. Remove spoofable identity headers before JWT assertion.
6. Replace pathname validation/open with descriptor-relative file traversal.
7. Capture one immutable responder/route snapshot per request.

Run adversarial resource-exhaustion, reset, symlink-race, spoofing, and reload
tests after each change. Repeat ASan and TSan.

### Phase 1 — make concurrency and memory genuinely bounded

1. Rework HTTP/1 request-body streaming around owned chunk transfer and bounded
   receive storage.
2. Move admission before task creation and bound every transport accept queue.
3. Separate application execution from I/O reactors while retaining single-owner
   protocol state.
4. Repair response-cache ownership/accounting and supervise revalidation.
5. Validate limit and key configuration at construction.

Measure RSS and allocation high-water marks under slow clients, slow handlers,
large uploads, connection floods, and mixed CPU/I/O workloads.

### Phase 2 — optimize after profiles identify the dominant costs

1. Add borrowed internal HTTP/2 and HTTP/3 frame walks.
2. Match routes once; benchmark cardinality before adopting a radix tree.
3. Shard WebSocket hub state only if actor profiling confirms contention.
4. Replace or rework allocating crypto primitives and precompute fixed auth
   state.
5. Tune executor count, socket sharding, watermarks, and buffer reuse from
   p95/p99 and allocation evidence, not peak trivial-route RPS alone.

### Phase 3 — close release gates

1. Make strict format/lint green.
2. Isolate/audit unsafe regions and enable Strict Memory Safety as a staged
   package/CI gate.
3. Pin mutable dependencies and produce reproducible resolution metadata.
4. Make HTTP/3 conformance/load checks reliable and required for supported
   configurations.
5. Commit controlled benchmark baselines with regression thresholds.
6. Update feature, security, conformance, deployment-floor, and streaming
   documentation from the tested implementation.
7. Remove verified dead code and add streaming response compression if it is a
   release requirement.

## Completion criteria

- No lossy transport-byte channel and no unbounded attacker-fed queue.
- Body/window memory bounded per stream, connection, and server under slow
  consumers.
- Stream resets and disconnects cancel all associated work without harming
  sibling requests.
- Handlers cannot block a reactor serving unrelated connections.
- Admission limits cover accepted, queued, handshaking, and active connections.
- Trusted identity headers are exclusively server-authored; file serving is
  race-safe.
- Tests, strict lint/format, strict-concurrency, ASan, TSan, conformance, and
  reproducible dependency checks are merge-gating.
- Performance changes have recorded before/after throughput, latency,
  allocation, RSS, CPU, and context-switch results with no safety regression.
