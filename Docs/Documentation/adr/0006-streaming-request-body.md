# ADR 0006 — Streaming request bodies

- **Status:** Accepted (HTTP/1.1 + HTTP/3 incremental; HTTP/2 buffered-as-stream, true-incremental staged)
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
- **HTTP/2 — buffered-as-stream (v1).** The sans-I/O engine still receives the whole body (bounded by the
  per-route limit) before surfacing `.request`; for a streaming route the server wraps those bytes as a
  one-shot `HTTPRequestBodyStream` (`HTTPServer.requestBody(_:for:)`). The handler API is **uniform across
  protocols** — `.stream` works everywhere — but on h2 the bytes are not yet delivered incrementally off
  the wire.

## Rationale

- **Conditional, not wholesale.** Streaming is a new path *alongside* the buffered one, gated by
  `streamsBody`. This keeps the engine `Event` model and its conformance tests untouched (a non-streaming
  request still yields one buffered `.request`), so the change is additive and low-risk.
- **Why h3 came before h2.** On HTTP/1.1 and HTTP/3 the read path is per-stream: HTTP/1.1's server *owns*
  the read loop, and each HTTP/3 request rides an independent QUIC stream served by its own task, so a feed
  loop can suspend on the handoff and let QUIC flow control back-pressure the sender — a local change. On
  HTTP/2 the sans-I/O engine buffers DATA and the *single* multiplexed serve loop replenishes the
  flow-control window *as it buffers*; truly incremental, back-pressured delivery requires gating window
  replenishment on handler consumption without the loop ever blocking on the handler (or it cannot read
  the `WINDOW_UPDATE` that unblocks the connection — the deadlock the response pump already guards
  against). That is the harder case, staged on its own after the shared engine `Event` split landed on
  HTTP/3.
- **Back-pressure is a refinement.** The v1 stream is `AsyncStream`-backed (no *producer* back-pressure):
  the body is bounded by the per-route limit, not by handler consumption. A 1-chunk request-direction
  handoff (mirroring the response `AsyncHandoff`) bounds memory below the limit and is the planned next
  step alongside the h2/h3 event split.

## Consequences

- `.stream` + `Route.streamingBody()` work end-to-end on **all three protocols**; HTTP/1.1 and HTTP/3
  deliver incrementally with back-pressure, HTTP/2 delivers the (limit-bounded) body wrapped as a stream.
- **Caveat — streamed-body errors surface as truncation, not status.** Once a streaming response's head
  is on the wire the server cannot send a `413`/`400`, so a chunked body that overruns the route limit
  mid-stream, or a truncated upload, ends the handler's stream early and closes the connection. The
  pre-buffer `413` is guaranteed only for Content-Length. Handlers must tolerate a body stream that ends
  abnormally.
- **Follow-ups** (tracked): the HTTP/2 incremental `Event` split + consumption-gated window replenishment
  for true wire-level streaming (the request-direction `AsyncHandoff` back-pressure is already in place,
  shared with HTTP/3); and, optionally, producer back-pressure for the HTTP/1.1 reader (still
  `AsyncStream`-backed, bounded by the per-route limit).
- New public API (`Route.streamingBody()`, `HTTPRequestBodyStream`, `RequestBody.stream`) carries doc
  comments + RFC citations; the streaming reader lives in `HTTPServer+RequestStreaming.swift`.
