# ADR 0006 — Streaming request bodies

- **Status:** Accepted and fully landed on all three protocols. HTTP/2 sub-limit back-pressure —
  consumption-gated window replenishment — landed 2026-07-31 as part of the audit's findings 2 and 4;
  see "Landed" at the end for the mechanism and the actual watermarks.
- **Context date:** 2026-06 (HTTP/2 back-pressure: 2026-07-31)

## Context

The request seam (ADR 0005) models a body as `RequestBody` — `.collected([UInt8])` or
`.stream(HTTPRequestBodyStream)` — but every engine produced only `.collected`. A framework on top of
this package needs to process a large upload *as it arrives* (bounded memory, early first-byte) rather
than buffering it whole, so the `.stream` case must actually be produced, opt-in per route, on every
protocol — without regressing the buffered hot path or the per-route body limit (ADR for Phase 1.2).

## Decision

- **Opt-in per route.** `Route.streamingBody()` sets `streamsBody`, surfaced through the
  `RouteResolver` seam (`ResolvedRoute.streamsBody`) the engines already query at the head for the body
  limit. A route that does not opt in is byte-for-byte unchanged (`.collected`), so existing handlers and
  the hot path are unaffected.
- **`HTTPRequestBodyStream`** is an `AsyncSequence` of `[UInt8]` chunks backed by an `AsyncStream`; the
  handler reads it with `for await chunk in body.asStream` or drains it with `await body.collect()`.
- **HTTP/1.1 — true incremental.** The reader (`serveStreaming`/`produceBody`,
  `HTTPServer+RequestStreaming.swift`) dispatches the handler with a `.stream` body **before** the body
  arrives, then reads the whole body off the wire (content-length or chunked) yielding each decoded chunk
  to the stream as it arrives. **Desync safety:** the server *always* reads the body to completion — even
  if the handler abandons the stream — so the keep-alive cursor stays exact and a pipelined follow-up
  request is never misaligned. `Expect: 100-continue` is honored before the body is read; an over-limit
  Content-Length is still pre-rejected with `413` before dispatch.
- **HTTP/3 — true incremental.** The engine splits the buffered `.request` into `.requestHead` →
  `.requestBodyChunk` → `.requestEnd`, gated per route on `streamsBody` (resolved at the head via a
  `resolveStreamsBody` closure the server builds from its `RouteResolver`); a non-streaming route is
  byte-for-byte unchanged (one buffered `.request`). Each request's per-stream task feeds the decoded
  chunks into a one-slot `AsyncHandoff` the handler consumes, suspending until the handler takes each one
  — and QUIC's per-stream flow control back-pressures the sender in turn, so an arbitrarily large upload
  is processed with bounded memory. The handler abandons the handoff on return, so the feed loop drains
  the rest of the body off the wire even if the handler stops reading early.
- **HTTP/2 — incremental, consumption-gated.** The engine splits the buffered `.request` into the same
  `.requestHead` → `.requestBodyChunk` → `.requestEnd` events, gated per route on `streamsBody`. The single
  multiplexed serve loop must never block on a handler (the deadlock the response pump also guards
  against), so the back-pressure is not "the producer waits" but "the peer is not given more window":
  each chunk goes into a byte-watermarked `BoundedByteChannel` and the receive window is credited only
  as the handler takes chunks out of it. See "Landed" below.

## Rationale

- **Conditional, not wholesale.** Streaming is a new path *alongside* the buffered one, gated by
  `streamsBody`. This keeps the engine `Event` model and its conformance tests untouched (a non-streaming
  request still yields one buffered `.request`), so the change is additive and low-risk.
- **Back-pressure differs by protocol, and so does its mechanism.** HTTP/3 rides an independent QUIC
  stream per request served by its own task, so the feed loop can simply suspend on a 1-slot handoff and
  QUIC's per-stream flow control back-pressures the sender. HTTP/1.1's server owns the read loop and
  drains on abandon, so its bound is the per-route limit. HTTP/2 can do neither: one loop multiplexes
  every stream, so suspending it would stop it reading the `WINDOW_UPDATE` that unblocks the connection.
  Its back-pressure therefore has to act on the *peer's window* rather than on the producer — which is
  what consumption gating does.

## Consequences

- `.stream` + `Route.streamingBody()` work end-to-end on **all three protocols**, delivering the body
  incrementally as it arrives. HTTP/2 and HTTP/3 both give sub-limit back-pressure (consumption-gated
  windows and QUIC flow control respectively); HTTP/1.1 still bounds memory by the per-route limit.
- **Caveat — streamed-body errors surface as truncation, not status.** Once a streaming response's head
  is on the wire the server cannot send a `413`/`400`, so a chunked body that overruns the route limit
  mid-stream, or a truncated upload, ends the handler's stream early and closes the connection. The
  pre-buffer `413` is guaranteed only for Content-Length. Handlers must tolerate a body stream that ends
  abnormally.
- **Follow-up** (tracked): the HTTP/1.1 reader is still `AsyncStream`-backed and bounded by the per-route
  limit rather than by handler consumption. It is a materially smaller exposure — one request in flight
  per connection, versus HTTP/2's `maxConcurrentStreams` — but the same class of bound.
- New public API (`Route.streamingBody()`, `HTTPRequestBodyStream`, `RequestBody.stream`) carries doc
  comments + RFC citations; the streaming reader lives in `HTTPServer+RequestStreaming.swift`.

## Landed: consumption-gated window replenishment (2026-07-31)

Staged on 2026-07-02 with a blocking analysis (kept below), and landed as part of the 2026-07-31
audit's findings 2 and 4. The prerequisite that analysis named — the serve-loop mailbox restructure —
had landed by then, which is what made this a contained change rather than a rewrite.

### Mechanism

The engine's receive accounting splits in two. `debitReceiveWindows` charges the peer's octets against
the connection and stream windows; `creditReceiveWindows` gives them back with a `WINDOW_UPDATE`
(RFC 9113 §6.9). The **buffered** path does both on arrival, exactly as before, because
`streams.totalBufferedBody` already bounds it connection-wide. The **gated** paths — a Phase 1.4
streaming route and an RFC 8441 tunnel, neither of which that aggregate covers — debit only.

The credit comes from the application:

1. the handler's `HTTPRequestBodyStream` iterator (or the tunnel pump) records each chunk's size into
   an `HTTP2ConsumptionSignal` as it **takes** it, and pokes the mailbox on the rising edge only;
2. the serve loop drains that counter on a `.consumed(streamID)` wakeup and calls
   `engine.replenishReceiveWindow`, which issues the `WINDOW_UPDATE`.

Neither side ever waits for the other, which is the constraint that shaped the design: the loop is the
engine's single owner and blocking it would stop it processing the very `WINDOW_UPDATE` that unblocks
the connection.

### The simplification that falls out

Once replenishment is consumption-gated, **the flow-control windows are the watermarks**. There is no
parallel accounting: unconsumed application bytes and outstanding receive credit are the same number,
by construction. The result is a hard bound of `connectionReceiveWindow` unconsumed bytes per
connection, regardless of stream count, route body limit, or handler behavior.

Retirement is what makes that bound exact rather than approximate. Every path that drops a gated stream
returns its outstanding credit to the shared connection window (§6.9.1, `HTTP2ConnectionState.retire`),
and a stream is retired at `requestReady` — the first moment nothing can consume its body — rather than
at `requestEnd`, when octets already queued are still held. Retiring at `requestEnd` would loosen the
bound to `connectionReceiveWindow + maxConcurrentStreams × streamReceiveWindow`.

### Watermarks

| Knob | default | `hardened` | `highThroughput` |
|---|---|---|---|
| `streamReceiveWindow` | 256 KiB | 64 KiB | 1 MiB |
| `connectionReceiveWindow` | 1 MiB | 256 KiB | 8 MiB |
| `bodyConsumptionTimeout` | 60 s | 30 s | 60 s |

RFC 9113 §6.9.2 fixes the connection window's initial value at 65,535 and `SETTINGS` cannot change it,
so the engine raises it with a stream-0 `WINDOW_UPDATE` as part of its preface.

### Cost

**Throughput.** A receive window of `W` at round-trip time `T` ceilings one connection's *upload* at
`W / T`. The 1 MiB default is ≈ 20 MB/s at 50 ms RTT, ≈ 100 MB/s at 10 ms, and effectively unlimited on
loopback. `highThroughput` raises it 8× (≈ 160 MB/s at 50 ms). This bounds a **single connection's
upload**, not aggregate request rate: the buffered path is untouched, so the 200k-rps target — which is
across many connections, with small or absent bodies — is unaffected.

**Head-of-line.** Because replenishment now depends on the application, a handler that stops reading
holds its share of the *shared* connection window shut and slows every sibling stream. That is HTTP/2's
own semantics — one connection, one window — and not something a server can design away. What it must
not be is unbounded, so a stream holding credit across two sweeps with no byte progress is reset with
`ENHANCE_YOUR_CALM` (§7) while its siblings continue. The rule is byte-progress based, not clock based;
the sweeper task only decides when to look.

**Per chunk.** One sequentially-consistent atomic pair and one coalesced mailbox wakeup per serve-loop
turn — tens of nanoseconds against a 16 KiB frame, on the opt-in streaming path.

## Staged: consumption-gated window replenishment — blocking analysis (2026-07-02)

> Superseded by "Landed" above; kept because it is the record of why the mailbox restructure had to come
> first, and every constraint it identified held.

Attempted as the staged refinement and **deliberately not landed**: the engine-side change is small,
but the correct design forces a serve-loop restructure whose regression surface (the h2 conformance +
fuzz suites, the response pump, the tunnels, graceful drain) exceeds what a safe increment can carry.
Recorded here so the next attempt starts from the design, not from scratch.

**What the refinement needs (engine side — small).** For a streaming route,
`receiveStreamingData` must stop replenishing on receipt (`consumeReceiveWindows` currently credits
the stream + connection windows back as DATA arrives, so the peer can always send up to the route
limit ahead of the handler). Instead: debit only, and expose
`replenish(_ streamID:, consumed n: Int)` that queues the stream + connection `WINDOW_UPDATE`s
(RFC 9113 §6.9) when called. A `Sendable` per-stream consumption counter (an `Atomic<Int>` box the
`HTTPRequestBodyStream` wrapper bumps as the handler's iterator delivers each chunk) carries
handler-side progress back; the serve loop drains counters and calls `replenish` — the loop stays the
engine's single owner, never blocking on a handler (the deadlock rule the response pump also obeys).

**The blocking constraint (loop side — the actual work).** The serve loop's only wait point is
`connection.receive(maxLength:)`. Once the peer has exhausted its window it stops sending — so the
loop parks in `receive` with nothing inbound — while the handler's consumption (the event that must
trigger `WINDOW_UPDATE`) has **no way to wake that parked read**. That is a genuine deadlock, not a
latency issue: peer waits for the window, loop waits for the peer. Consumption-gated replenishment
therefore requires the loop's wait point to become a **merged mailbox** —
`AsyncStream<Wakeup>` of `.inbound(bytes)` | `.consumed` | `.shutdown` — with a reader child task
owning `connection.receive` and feeding `.inbound`, exactly the wakeup pattern the WebSocket driver
already uses (`WebSocketWakeup`). The single-owner model survives intact (the loop remains the sole
engine toucher); what changes is *every* h2 read path: the main keep-alive loop, the response pump's
window-blocked `drainInboundWhileBlocked` (which today performs its own receive and must instead
consume the same mailbox, or the two readers race the socket), the h2 WebSocket tunnels, and the
GOAWAY drain sequencing — each re-routed and each covered by conformance tests that assume the
current read topology.

**Prerequisite now in place.** The mailbox pattern's teardown (`reader.cancel()` on loop exit) only
works on real sockets since this branch's per-park receive-cancellation fix (S1) — before it, a
cancelled reader child task leaked its parked receive on every socket backbone. That fix was landed
independently precisely so this restructure can follow.

**Shared unlock.** The same mailbox restructure is the enabler for the other documented v1 ceiling —
multiplexed concurrent h2 **streamed responses** (P6b/S4: one streamed response at a time, siblings
answered buffered between chunks): with the loop consuming a mailbox, per-stream producer tasks can
signal readiness the same way consumption does. Do both in one restructure; doing either alone pays
the full regression cost for half the value.

**Recommended shape for the attempt:** (1) land the mailbox + reader-task restructure with byte-
identical behavior (no window change) behind the full h2 conformance/fuzz gate; (2) flip streaming
routes to debit-only windows + counter-driven `replenish` (a `WINDOW_UPDATE`-order test per RFC 9113
§6.9, a stalled-handler test proving the peer stalls at the window, and a consumption-resume test);
(3) lift the response-side single-stream ceiling. Each step separately gated.
