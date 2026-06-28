# Server Feature Gap Analysis

What features does a full-featured HTTP server provide, and where does **this** server stand against
them? This audit pairs a full inventory of our codebase against the reference servers installed on this
machine (nginx 1.31.2, Caddy 2.11.4, Apache httpd) and the broader landscape (Envoy, HAProxy, Traefik,
and the modern app-server frameworks), then names our gaps and what to do about each.

> **Method.** Our column is grounded in a code-level inventory (every middleware, parser, and limit was
> read, not assumed). The reference columns reflect the documented, stable feature sets of those servers
> — see the cited, 14-category companion taxonomy in
> [`2026-06-25-server-feature-taxonomy-reference.md`](2026-06-25-server-feature-taxonomy-reference.md)
> (~180 sources) for the full matrices behind the summaries here.
> Legend: ✅ built-in · ◐ partial / via module / platform-delegated · ✗ absent.
>
> **Read the reference ✅s with a grain of salt.** Many "yes" cells for the big servers are *commercial
> or add-on*: active health checks, cookie stickiness, JWT, and cluster rate-limit sync are **nginx
> Plus-only**; native JWT/OIDC and the high-perf WAF are **Traefik Hub/Enterprise**; nginx brotli/GeoIP
> are third-party modules; Caddy rate-limiting/WAF/JWT need an `xcaddy` custom build. So our gap to the
> *open-source, out-of-the-box* posture is often smaller than a raw matrix suggests.

## 0. First, the right comparison

"Full-featured server" spans **two different product classes**, and conflating them produces a unfair
gap list:

- **Edge / reverse-proxy servers** — nginx, Caddy, Envoy, HAProxy, Traefik. Their job is to sit *in
  front of* applications: terminate TLS, route/load-balance to upstreams, cache, rate-limit, do ACME.
- **Origin application servers / HTTP libraries** — our server, SwiftNIO/Hummingbird/Vapor, Go
  `net/http`, Rust `axum`/`actix`, Node `express`/`fastify`. Their job is to *be* the application: parse
  requests, route to handlers, run middleware, write responses.

**We are firmly in the second class** — and the docs say so (stated non-goals: reverse proxy, load
balancing, WAF, ACME, OAuth). So a missing reverse proxy isn't a defect; it's the thing you put *in
front* of us. The analysis below judges us primarily as an **origin app server**, and flags edge-proxy
features only to be complete (you compose those, you don't build them into an app server).

The one cross-cutting exception is **platform**: every reference server is Linux-first, and servers run
on Linux. See §3, gap G0.

## 1. Executive summary

**Where we lead even the big servers:** protocol breadth built from scratch (HTTP/1.1 + HTTP/2 + HTTP/3
+ WebSocket, all first-party, no NIO), and **security-hardening depth** — named-CVE defenses (Rapid
Reset, CONTINUATION flood, MadeYouReset), request-smuggling rejection, decompression-bomb caps,
slowloris timeouts, strict-ALPN, TLS-1.3 floor — designed-in with RFC/CVE citations rather than patched
reactively. As an *app server*, our routing, middleware breadth (25 middlewares), rate-limiting, and
request-limit posture are at or above the norm for the peer class.

**Where the real, in-class gaps are** (things a complete *app server* is expected to have):
1. **Linux support** (G0) — biggest practical gap; we're Apple-only.
2. **Observability bridges** (G1) — no structured-logging / Prometheus / OpenTelemetry exporters (only seams).
3. **Outbound Brotli/Zstd** (G2) — we decompress them inbound but only emit gzip.
4. **mTLS / client certificates** (G3).
5. **Graceful config & certificate reload** (G4) — restart required today.
6. **Static-serving completeness** (G5) — no sendfile/zero-copy, autoindex, or precompressed-file serving.
7. **HTTP/3 + QPACK-dynamic and HTTP/2 priority scheduling** (G6) — engines present but partial.
8. **Auth helpers** (G7) — only signed session cookies; no Basic/JWT/OAuth building blocks.

**Deliberately out of scope** (compose an edge proxy instead): reverse proxy, load balancing, ACME /
auto-HTTPS, OCSP stapling, edge/proxy caching, WAF.

## 2. Feature matrix

### Protocols
| feature | ours | nginx | Caddy | Apache | notes |
|---|:--:|:--:|:--:|:--:|---|
| HTTP/1.1 | ✅ | ✅ | ✅ | ✅ | RFC 9112; smuggling defenses built-in |
| HTTP/2 | ✅ | ✅ | ✅ | ✅ | h2 + h2c (prior knowledge); h2spec 144/146 |
| HTTP/3 / QUIC | ◐ | ✅ | ✅ | ◐ | engine complete; QUIC via Network.framework; QPACK dynamic partial |
| WebSocket | ✅ | ✅ | ✅ | ✅ | **native handler** (we terminate); proxies only tunnel it. h1 + h2 (RFC 8441); permessage-deflate |
| Server-Sent Events | ✅ | ✅ | ✅ | ✅ | native streaming + `.serverSentEvents` |
| gRPC | ✗ | ✅ | ✅ | ◐ | we have h2 + trailers substrate but no gRPC service layer |

### TLS & certificate management
| feature | ours | nginx | Caddy | Apache | notes |
|---|:--:|:--:|:--:|:--:|---|
| TLS 1.2 / 1.3, ALPN | ✅ | ✅ | ✅ | ✅ | **TLS 1.3-only by default** (stricter than most); ALPN strict (ALPACA defense) |
| SNI multi-cert selection | ◐ | ✅ | ✅ | ✅ | single identity today; no per-host cert selection |
| mTLS / client certs | ✗ | ✅ | ✅ | ✅ | **gap G3** |
| OCSP stapling | ✗ | ✅ | ✅ | ✅ | edge concern — **and now legacy**: Let's Encrypt killed OCSP (Aug 2025, CRL-only), so not having it barely matters |
| ACME / auto-HTTPS | ✗ | ✗¹ | ✅ | ◐ | out of scope; Caddy's signature feature (¹nginx needs certbot) |
| Cert hot-reload | ✗ | ✅ | ✅ | ✅ | **gap G4** |

### Routing & request handling
| feature | ours | nginx | Caddy | Apache | notes |
|---|:--:|:--:|:--:|:--:|---|
| Path/method routing, params, wildcards | ✅ | ✅ | ✅ | ✅ | result-builder DSL; groups + per-group middleware |
| Auto OPTIONS / 405+Allow / 404 | ✅ | ◐ | ◐ | ◐ | folded into the router (RFC 9110) |
| Content negotiation | ◐ | ✅ | ✅ | ✅ | Accept-Encoding handled; no Accept/Accept-Language negotiation helper |
| Redirects / rewrites | ◐ | ✅ | ✅ | ✅ | done in handlers/middleware; no declarative rewrite DSL |

### Static files
| feature | ours | nginx | Caddy | Apache | notes |
|---|:--:|:--:|:--:|:--:|---|
| Range / conditional / ETag / streaming | ✅ | ✅ | ✅ | ✅ | `FileResponder`; traversal-safe |
| sendfile / zero-copy | ✗ | ✅ | ✅ | ✅ | **gap G5** |
| Directory autoindex | ✗ | ✅ | ✅ | ✅ | **gap G5** |
| Precompressed (`.br`/`.gz`) serving | ✗ | ◐ | ✅ | ◐ | **gap G5** |

### Compression / caching
| feature | ours | nginx | Caddy | Apache | notes |
|---|:--:|:--:|:--:|:--:|---|
| gzip out / inbound decompress | ✅ | ✅ | ✅ | ✅ | inbound gzip+deflate+brotli (bomb-capped) |
| Brotli / Zstd **out** | ✗ | ◐ | ✅ | ◐ | **gap G2** (we decode br inbound but can't emit it) |
| Origin response cache | ◐ | ✅ | ✅ | ✅ | RFC 9111 freshness + conditional; revalidation deferred |
| Proxy / edge cache | ✗ | ✅ | ✅ | ✅ | out of scope (edge concern) |

### Reverse proxy / load balancing  *(edge class — out of scope by design)*
| feature | ours | nginx | Caddy | Envoy/HAProxy | notes |
|---|:--:|:--:|:--:|:--:|---|
| Upstreams, health checks, LB algos, retries, circuit-breaking | ✗ | ✅ | ✅ | ✅✅ | compose a proxy in front; not an app-server feature |

### Traffic control & security hardening
| feature | ours | nginx | Caddy | Apache | notes |
|---|:--:|:--:|:--:|:--:|---|
| Rate limit / conn limit / body limit | ✅ | ✅ | ◐ | ◐ | sliding-window + per-client/global conn caps + 413 |
| Timeouts / slowloris defense | ✅ | ✅ | ✅ | ✅ | header-read/idle/keep-alive timeouts |
| Named-CVE defenses (Rapid Reset, CONTINUATION flood, MadeYouReset) | ✅ | ◐ | ◐ | ◐ | **we lead** — designed-in, CVE-cited |
| Request-smuggling / header-injection rejection | ✅ | ✅ | ✅ | ✅ | RFC 9112 strict |
| Security headers / CORS | ✅ | ◐ | ✅ | ◐ | dedicated hardened middleware |
| WAF | ✗ | ◐ | ◐ | ◐ | via modsecurity/coraza; out of scope (middleware-extensible) |

### Observability
| feature | ours | nginx | Caddy | Apache | notes |
|---|:--:|:--:|:--:|:--:|---|
| Access / error logs | ✅ | ✅ | ✅ | ✅ | closure-based; no structured-log format presets |
| Metrics / Prometheus | ◐ | ◐ | ✅ | ◐ | `HTTPMetrics` seam only; no exporter — **gap G1** |
| Tracing / OpenTelemetry | ✗ | ◐ | ✅ | ✗ | **gap G1** (planned P9) |
| Health / readiness endpoint | ◐ | ◐ | ✅ | ◐ | example route only; not built-in |

### Config, ops & extensibility
| feature | ours | nginx | Caddy | Apache | notes |
|---|:--:|:--:|:--:|:--:|---|
| Graceful shutdown / drain | ✅ | ✅ | ✅ | ✅ | per-connection drain, GOAWAY |
| Hot config reload (zero downtime) | ✗ | ✅ | ✅ | ✅ | **gap G4** |
| Worker / prefork model | ✅ | ✅ | ✅ | ✅ | 4 transport backbones + SO_REUSEPORT prefork |
| Extensibility (middleware/modules) | ✅ | ◐ | ✅ | ✅ | clean Swift middleware + responder + backbone protocols |
| **Cross-platform (Linux)** | ✗ | ✅ | ✅ | ✅ | Apple-only — **gap G0** |

## 3. The gaps, prioritized

### Tier 1 — close these to be a complete origin app server
- **G0 · Linux support.** *Biggest practical gap.* Servers run on Linux; we're macOS/iOS only. The
  sans-I/O engines are already pure and portable — the lift is a POSIX/epoll transport backbone and a
  non-Network.framework TLS path (e.g. swift-certificates/swift-nio-ssl-free BoringSSL or system
  OpenSSL). This single gap gates real-world server deployment more than any feature below.
- **G1 · Observability bridges.** We have a clean `HTTPMetrics` seam and closure logging but ship no
  exporters. Add swift-log, swift-metrics (Prometheus), and swift-distributed-tracing (OpenTelemetry)
  bridges + a built-in `/healthz` readiness handler. (Already scoped as roadmap P9.)
- **G2 · Outbound Brotli (and Zstd).** We *decode* Brotli inbound but only *emit* gzip. Brotli-out is
  table stakes for static/text responses; wire the system `COMPRESSION_BROTLI` encoder into
  `CompressionMiddleware` with content-type/size gating and quality config.
- **G3 · mTLS / client certificates.** Network.framework supports client-cert auth; expose it
  (request/require modes + a verified-identity hook to handlers). Common for service-to-service and
  zero-trust deployments.

### Tier 2 — strengthens us; schedule after Tier 1
- **G4 · Graceful config & certificate reload.** Rotate certs and swap the responder/route table
  without dropping connections (today: restart). Pairs naturally with the existing graceful-shutdown
  drain.
- **G5 · Static-serving completeness.** sendfile/zero-copy (throughput), directory autoindex, and
  precompressed-file serving (`.br`/`.gz` sidecars) — all standard in the reference servers.
- **G6 · Finish the modern-protocol tail.** QPACK dynamic-table encoder/decoder integration + h3
  blocked-stream handling; HTTP/2 RFC 9218 priority *scheduling* (field is parsed today, not yet used
  to order writes); RFC 9220 WebSocket-over-HTTP/3.
- **G7 · Auth building blocks.** Basic auth, bearer/JWT verification, and an `auth_request`-style hook
  as middleware (we have signed sessions only). Keep OAuth/OIDC flows out (app concern), but ship the
  verification primitives.

### Deliberately out of scope — don't build, compose
Reverse proxy / upstreams / load balancing, ACME / auto-HTTPS, OCSP stapling, proxy/edge caching, and
WAF are **edge-proxy** responsibilities. The right architecture is our app server **behind** nginx /
Caddy / Envoy, which already do these well. Building them in would duplicate mature tools and bloat a
library whose value proposition is a safe, fast, dependency-light origin. (All are listed as explicit
non-goals in the project docs.)

## 4. Bottom line

As an **origin application server**, we are *feature-competitive and security-ahead* of the peer class,
with unusually broad from-scratch protocol support. The gaps that actually matter for shipping are
**operational**, not protocol: **Linux (G0)**, **observability (G1)**, and a few response-side niceties
(**Brotli-out G2**, **mTLS G3**, **reload G4**, **static completeness G5**). Closing G0–G3 would make
this a genuinely deployable, production-grade app server; the edge-class features should stay where they
belong — in the proxy in front of us.

## Appendix — environment & scope notes

- **Full cited reference:** the 14-category feature×server taxonomy with ~180 source URLs lives in
  [`2026-06-25-server-feature-taxonomy-reference.md`](2026-06-25-server-feature-taxonomy-reference.md).
- **Reference servers inspected on host:** nginx 1.31.2 (mainline, OpenSSL 3.6.2), Caddy 2.11.4 (133
  modules), Apache httpd 2.4.66 (prefork MPM). HAProxy / Envoy / Traefik not installed (assessed from
  documentation).
- **Currency notes that shift the landscape:** HTTP/2 Server Push is **dead** (Chrome 106 / Firefox 132
  / nginx 1.25.1) — not a gap for anyone; OCSP stapling is **legacy** (LE CRL-only since Aug 2025); ECH
  (RFC 9849, Mar 2026) is the new TLS frontier, native only in nginx 1.29.4+ / experimental Caddy.
- **Our inventory source:** code-level audit of `Sources/**` (protocols, transport, server, routing, 25
  middlewares, `HTTPLimits`, security guards) cross-checked against `README.md`, `CLAUDE.md`,
  `Docs/Standards/CONFORMANCE.md`, and the completion roadmap.
- **Stated design constraints (from docs):** SwiftNIO-free; Apple-platforms-first; Swift 6 strict
  concurrency/memory; sans-I/O engines; standards-first (every parser cites its RFC); near-zero
  dependencies. These constraints explain several scope choices above.
