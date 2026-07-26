# ADR 0005 — The explicit request seam (`RequestContext` + `RequestBody`)

- **Status:** Accepted
- **Context date:** 2026-06

## Context

The responder seam was `HTTPResponder.respond(to: HTTPRequest, body: [UInt8])`. It was too thin to be a
foundation for a framework: it dropped every piece of per-request connection context (peer address, the
verified mutual-TLS subject, `isSecure`, the negotiated ALPN protocol, the connection id), it always
buffered the whole body, it carried no place for middleware to hand typed data to a handler, and it had
nowhere to put a per-request deadline. Two workarounds had accreted around the gap: the verified TLS
client-certificate subject was smuggled to handlers by **stamping it onto the request as an
`X-Client-Cert-Subject` header** (`HTTPServer+ClientCert.swift`), and a matched route's captured
parameters were flowed to group middleware through a **`Route.currentParameters` task-local**.

A downstream framework (ADServe) re-basing onto this package needs all of that context, plus a streamable
body and per-route configuration. The seam is the linchpin: widening it unblocks per-request context,
streaming bodies, per-route body limits, body codecs, and per-request timeouts at once.

## Decision

Thread two explicit value types through the seam, and change the three responder/middleware/handler
signatures to carry them:

```swift
func respond(to: HTTPRequest, body: RequestBody, context: RequestContext) async -> ServerResponse
func respond(to:body:context:next:)                      // HTTPMiddleware
typealias Route.Handler = (HTTPRequest, RequestBody, RequestContext) async -> ServerResponse
```

- **`RequestContext`** — a `struct` carrying `connection` (peer, `tlsPeerSubject`, `isSecure`,
  `negotiatedApplicationProtocol`, `id`), a correlation `id`, the matched route's `parameters`, an
  optional `deadline`, and a **type-keyed storage bag** (`subscript<Key: RequestStorageKey>`,
  `EnvironmentValues`-style) for middleware→handler data.
- **`RequestBody`** — an `enum`: `.collected([UInt8])` (today's default) or `.stream(HTTPRequestBodyStream)`
  (a back-pressured `AsyncSequence` of chunks, mirroring the response's `ResponseStream`). Accessors
  `collect()` (buffered) and `asStream` (incremental) work regardless of case.

The server builds the context once at each protocol-engine dispatch point — from the
`TransportConnection` (HTTP/1.1, HTTP/2) or `QUICConnection` (HTTP/3) — and passes it in. The
`X-Client-Cert-Subject` header stamp is **retired**: the verified subject now reaches handlers as
`context.connection.tlsPeerSubject`. The `Route.currentParameters` task-local is **removed**: the router
folds the captures into `context.parameters`, which threads down the group-middleware chain by value.

Both protocols also gain `[UInt8]`-body **convenience overloads** (`respond(to:body:)` /
`respond(to:body:next:)`, default/explicit context) so tests and simple call sites invoke the seam
without constructing a context.

## Rationale

1. **Allocation-lean hot path.** `RequestContext` is a `struct` of value-type metadata, so the common
   request adds no heap allocation over the old `[UInt8]` seam. The storage bag is the only reference: a
   **lazily-allocated, copy-on-write box** that defaults to a shared empty sentinel, so a request that
   touches no storage allocates nothing, and the first write copies the sentinel into a fresh box.
   Value semantics (COW on non-unique mutation) keep one request's writes from leaking sideways.
2. **No eager work for unused features.** The server does **not** mint a correlation id on the hot path
   (it adopts a valid inbound `X-Request-ID`, else leaves `id` nil); `RequestIDMiddleware` mints one and
   writes it back to `context.id` only when installed. Streaming production is deferred; until then every
   body arrives `.collected`, and the stream accessors already work so the public shape is stable.
3. **Security improves by construction.** The verified client-cert subject is a server-asserted *value*,
   never a header derived from the wire — a client cannot spoof it, and a hostile subject containing
   CR/LF cannot inject a header line (CWE-93), because there is no header to inject.
4. **One breaking change, broad payoff.** Pre-1.0, a single widening of the seam is preferable to a
   sequence of additive shims; it unblocks the per-request-context, streaming-body, per-route-limit,
   codec, and timeout work behind one migration.

## Consequences

- **Breaking API change**, migrated across the responder/middleware protocols, the router and route
  handler, the ~23 middleware, the three engine call sites, the example, the benchmark, and the test
  suite. The 987-test suite is the safety net (all green after the change).
- `HTTPServer+ClientCert.swift` is deleted; the cert-subject tests now assert delivery via
  `context.connection.tlsPeerSubject` (a value), not a stamped header.
- `Route.currentParameters` (the task-local) is gone; group middleware receives parameters on the
  context, so the precomputed-chain optimization (audit #9) is preserved without a task-local.
- New public surface carries doc comments + RFC citations; files follow the repo's
  one-declaration-per-file / no-grouping-extension conventions (`RequestContext`, `RequestBody`,
  `RequestStorageKey`, `HTTPRequestBodyStream` each in their own file).
- **Follow-on, unblocked by this seam:** streaming request bodies need their own back-pressure /
  cancellation ADR; per-route body limits, body codecs, and the per-request 504 timeout build on the
  context fields landed here.
