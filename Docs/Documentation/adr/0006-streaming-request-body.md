# ADR 0006 — Streaming request bodies

- **Status:** Accepted (incremental on all three protocols; HTTP/2 sub-limit back-pressure staged —
  see the 2026-07-02 blocking analysis at the end: the design is settled, the safe increment is a
  serve-loop mailbox restructure to be landed behind its own conformance gate)
- **Context date:** 2026-06

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
- **HTTP/2 — incremental, limit-bounded.** The engine splits the buffered `.request` into the same
  `.requestHead` → `.requestBodyChunk` → `.requestEnd` events, gated per route on `streamsBody`. The single
  multiplexed serve loop must never block on a handler (the deadlock the response pump also guards
  against), so it feeds each chunk into an *unbounded* `AsyncStream` the handler consumes — incremental
  delivery, with memory bounded by the per-route limit the engine enforces (chunks accumulate only while
  the handler lags, never beyond the cap). This matches HTTP/1.1's back-pressure class; sub-limit
  back-pressure (consumption-gated window replenishment) is the remaining HTTP/2 refinement.

## Rationale

- **Conditional, not wholesale.** Streaming is a new path *alongside* the buffered one, gated by
  `streamsBody`. This keeps the engine `Event` model and its conformance tests untouched (a non-streaming
  request still yields one buffered `.request`), so the change is additive and low-risk.
- **Back-pressure differs by protocol.** HTTP/3 gives true sub-limit back-pressure: each request rides an
  independent QUIC stream served by its own task, so the feed loop suspends on a 1-slot handoff and QUIC's
  per-stream flow control back-pressures the sender. HTTP/1.1 (the server owns the read loop, draining on
  abandon) and HTTP/2 (the shared multiplexed loop must never block on a handler) deliver incrementally but
  bound memory by the per-route limit rather than handler consumption. True HTTP/2 sub-limit back-pressure
  requires consumption-gated window replenishment — debit the window as the peer sends, replenish only as
  the handler consumes (signalled by a `Sendable` counter the loop drains, never blocking on the handler,
  or it cannot read the `WINDOW_UPDATE` that unblocks the connection) — the documented follow-up.
- **Back-pressure is a refinement.** The v1 stream is `AsyncStream`-backed (no *producer* back-pressure):
  the body is bounded by the per-route limit, not by handler consumption. A 1-chunk request-direction
  handoff (mirroring the response `AsyncHandoff`) bounds memory below the limit and is the planned next
  step alongside the h2/h3 event split.

## Consequences

- `.stream` + `Route.streamingBody()` work end-to-end on **all three protocols**, delivering the body
  incrementally as it arrives; HTTP/3 adds sub-limit (QUIC flow-control) back-pressure, while HTTP/1.1 and
  HTTP/2 bound memory by the per-route limit.
- **Caveat — streamed-body errors surface as truncation, not status.** Once a streaming response's head
  is on the wire the server cannot send a `413`/`400`, so a chunked body that overruns the route limit
  mid-stream, or a truncated upload, ends the handler's stream early and closes the connection. The
  pre-buffer `413` is guaranteed only for Content-Length. Handlers must tolerate a body stream that ends
  abnormally.
- **Follow-ups** (tracked): HTTP/2 sub-limit back-pressure via consumption-gated window replenishment; and,
  optionally, the same for the HTTP/1.1 reader (both currently `AsyncStream`-backed, bounded by the
  per-route limit). The request-direction `AsyncHandoff` back-pressure is already in place on HTTP/3.
- New public API (`Route.streamingBody()`, `HTTPRequestBodyStream`, `RequestBody.stream`) carries doc
  comments + RFC citations; the streaming reader lives in `HTTPServer+RequestStreaming.swift`.

## Staged: consumption-gated window replenishment — blocking analysis (2026-07-02)

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
