# ADServe-migration findings — dispositions (2026-07-02)

Re-basing ADServe (the downstream result-builder framework) onto this package surfaced six findings
against the public seams — two severity-graded bugs and four API gaps. This records each with its
disposition; the fixes landed on this branch (commits cited), the additive follow-ups are tracked in
the gap-closing roadmap. Two Linux blockers found while verifying the fixes ride along at the end.

## 1 · [S1 · fixed] Socket backbones' `receive` ignored task cancellation

The kqueue/dispatch (and epoll/swift-system/Network/portable-TLS) backbones parked reads in
continuations that only the SERVE-task-level cancellation handler (`connection.cancel()`, audit CC4)
unblocked. A **child-task** cancel — exactly what the server's own idle watchdog issues
(`withIdleWatchdog` cancels the serve-loop child, so the serve-task handler never fires) — left a
real-socket receive parked forever; the in-repo idle test passed only because the `HangingConnection`
fake honors cancellation itself. The `TransportConnection` contract documented receive as cancellable.

**Disposition — fixed** (`fix(transport): honor task cancellation on a parked receive…`): every
socket backbone installs a per-**park** cancellation handler (the data-ready hot path stays free of
cancellation bookkeeping, preserving audit CC4); a cancelled receive tears the connection down and
throws `CancellationError`. Regression tests: a bare child-task cancel unblocks a parked
`receive(maxLength:)` and `receive(into:)` on all four Darwin socket backbones over real loopback
sockets, plus the portable-TLS twin over a socketpair. The same audit hardened refused readiness
registrations (EBADF after a concurrent close) and closed a close-sweep window in which a callback
could have read a kernel-reused descriptor number.

## 2 · [S2 · fixed] h1 parse-time body limit ran before route resolution

`RequestParser.resolveFraming` enforced the global `HTTPLimits.maxBodySize` on a declared
`Content-Length` at parse time — before the `RouteResolver` ran — so a route's `bodyLimited(to:)`
could tighten but never RAISE the global bound, contradicting the Phase-1.2 semantics. h2/h3
additionally `min()`ed the resolved limit with the global.

**Disposition — fixed** (`fix(h1): enforce the body limit after route resolution…`): the size policy
runs after resolution on all three protocols (`resolved ?? global` — raise or tighten), still before
buffering; the h2/h3 connection-level aggregate buffer bound stretches to
`max(global, the stream's route cap)` so total memory stays bounded by the largest declared route
limit. The same commit decoupled the WebSocket message cap from `maxBodySize`
(`HTTPLimits.maxWebSocketMessageSize`, `nil` = follow `maxBodySize`) and closed an engine gap where a
SINGLE unfragmented frame bypassed `maxMessageSize` (RFC 6455 §5.4; Close 1009).

## 3 · [G3 tail · fixed] mTLS context was leaf-subject-only; PKCS#12-only intake; no trust-roots seam

Handlers saw only `tlsPeerSubject: String?`; ADServe needed the presented chain and SANs for real
authorization, had to shell out to `openssl pkcs12` to build identities, and hand-rolled CA
validation in `verifyPeer`.

**Disposition — fixed** (`feat(transport): G3 tail…`): `TLSPeerIdentity` (DER chain leaf-first, leaf
subject, leaf SANs via a shared bounds-checked DER walk — RFC 5280 §4.2.1.6) rides
`TransportConnection`/`QUICConnection` and `RequestContext.Connection` on all three protocols;
`TransportTLS.PEMIdentity` intake (portable backbone native; the Network backbone documents the
Security-framework gap — no public in-memory cert+key → `SecIdentity`, PKCS#12 stays the Darwin
container); `TransportTLS.chainValidator(roots:)` — RFC 5280 §6 path validation with pinned anchors
(SecTrust on Darwin, BoringSSL `X509_STORE` on the portable backbone).

## 4 · [gap · upstreamed] UNIX-domain-socket backbone

ADServe ships its own UDS `TransportBackbone` on the public seam (reverse-proxy upstream sockets,
sidecars). **Disposition:** upstream a first-class UDS variant of the POSIX backbones — see the
additive-API slice on this branch / the G-series follow-up if it slips.

## 5 · [gap · evaluated] Connection-level WebSocket lifecycle hooks (`onOpen`/`onClose`)

ADServe wants explicit open/close callbacks per WebSocket connection. **Disposition:** evaluated
against the event/action model — see the additive-API slice notes: the contract remains
`WebSocketHandler.handle(event) -> [action]`; open is observable today as the first event delivery
(and via `shouldUpgrade`), close via the `.close` event. If first-class hooks are added they must be
optional protocol requirements defaulting to no-ops so every existing handler is unaffected.

## 6 · [gap · additive] `HTTPStatus.reasonPhrase` + `maxConnections` admission visibility

ADServe re-implements the reason-phrase table because `HTTPStatus.reasonPhrase` is not public, and an
over-`maxConnections` connection is closed silently (the admission gate cannot send a `503` — by
design the cap must not spend serve resources on the rejected connection; a load balancer reads the
RST). **Disposition:** make `reasonPhrase` public (additive-API slice); keep the silent close and
document the rationale here — emitting a `503 Service Unavailable` (RFC 9110 §15.6.4) would require
parsing the request head of a connection the cap exists to shed (amplification under overload), so
the fast close is deliberate; `maxConnectionsPerClient` rejections behave the same.

## Linux blockers found while verifying (fixed on this branch)

- `EpollEventLoop`'s `eventfd(2)` calls could never have compiled on Linux: Glibc's modulemap exposes
  neither `<sys/eventfd.h>` nor the `EFD_*` flags — routed through the `CEpoll` shim
  (`CEpoll_eventfd` / `CEpoll_eventfd_wakeup_flags`), the same precedent as `<sys/epoll.h>` itself.
- `DateCache`'s `pthread_key_create` destructor: Glibc imports the parameter as an *optional*
  pointer (Darwin: non-optional), so the tail-latency-audit per-thread cache broke the Linux build —
  platform-split unwrap (POSIX.1-2017 guarantees a non-NULL invocation).
