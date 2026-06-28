# Production HTTP/Web Server Feature Taxonomy — reference

Companion reference for [`2026-06-25-server-feature-gap-analysis.md`](2026-06-25-server-feature-gap-analysis.md).
The canonical, **cited** feature set expected of production HTTP servers and reverse proxies, organized
into 14 categories, each with a feature×server support matrix (nginx · Apache · Caddy · HAProxy · Envoy ·
Traefik), a table-stakes-vs-advanced classification, and an app-server-framework note. Compiled from
current (mid-2026) vendor documentation plus local inspection of the servers installed on the audit
host. The gap analysis draws its reference columns from this document; consult the per-category Sources
at the end for primary links.

> **Currency flags (material shifts captured here):**
> 1. **HTTP/2 Server Push is dead** — disabled in Chrome 106 (Oct 2022), removed from Firefox 132 and
>    from nginx 1.25.1. Use `103 Early Hints`. Treat as a non-feature.
> 2. **OCSP stapling is now legacy** — Let's Encrypt shut off its OCSP responders (Aug 6 2025) and
>    dropped OCSP URLs from certs (CRL-only), demoting stapling/Must-Staple to effectively unusable
>    with LE certs.
> 3. **ECH (Encrypted Client Hello)** — newest TLS frontier (RFC 9849, finalized Mar 2026); only
>    nginx 1.29.4+ and experimental Caddy 2.10 ship it natively.
> 4. **Open-source-vs-commercial gates** — several reference-server "yes" cells are paid/module-gated:
>    nginx Plus-only (active health checks, cookie stickiness, JWT, dynamic upstream API, cluster
>    rate-limit sync); Traefik Hub/Enterprise (native JWT/OIDC, WAF); nginx third-party (brotli, GeoIP,
>    ModSecurity); Caddy `xcaddy` custom build (rate limiting, WAF, JWT). Weigh these when reading a ✅.

---

## Part A — Locally installed servers (inspected on the audit host)

| Server | Version | Notes from local inspection |
|---|---|---|
| **nginx** | **1.31.2** (mainline) | OpenSSL 3.6.2, TLS SNI. Compiled-in: `http_v2`, `http_v3` (HTTP/3/QUIC), `http_ssl`, `stream`(+`ssl`+`ssl_preread`), `mail`, `realip`, `sub`, `dav`, `gzip_static`, `gunzip`, `secure_link`, `slice`, `auth_request`, `addition`, `random_index`, `stub_status`, `degradation`, `flv`/`mp4`, PCRE2+JIT, `--with-compat`, `--with-debug`. **Absent:** brotli (`ngx_brotli` 3rd-party), `perl`, GeoIP2. Active health checks / JWT / cluster rate-limit-sync are **Plus-only**. |
| **Caddy** | **v2.11.4** | 133 modules. h1/h2/h3 native; `encoders.gzip`+`encoders.zstd` on-the-fly; `precompressed.br`/`.gzip`/`.zstd` (brotli serve-only, no on-the-fly br encoder); full `reverse_proxy` policies + dynamic upstreams; FastCGI; `acme_server`; `authentication` (basic, argon2id/bcrypt); `tracing` (OTel); `metrics` (Prometheus); CEL `expression` matcher. **Needs `xcaddy`:** rate limiting, WAF (Coraza), JWT, GeoIP. |
| **Apache httpd** | **2.4.66** (Unix) | MPM **prefork** (this build; `event` is the modern distro default). APR 1.5.2, PCRE 10.42. `APR_HAS_SENDFILE`+`APR_HAS_MMAP` (zero-copy + mmap static). `mod_so` DSO loading; everything (mod_http2, mod_ssl, mod_proxy, mod_deflate, mod_brotli, mod_md…) loaded as runtime DSOs. |
| **HAProxy** / **Envoy** / **Traefik** | not installed | Assessed from documentation. |

---

## Part B — Feature taxonomy

## 1. Protocols
**Expected:** HTTP/1.0 & 1.1 (keep-alive; pipelining is dead); HTTP/2 (multiplexing, HPACK, ALPN `h2`);
h2c (cleartext h2, internal hops); **HTTP/2 Server Push — dead**; HTTP/3/QUIC (+0-RTT, `Alt-Svc`);
WebSocket (RFC 6455; permessage-deflate negotiated end-to-end, proxies tunnel it); gRPC / gRPC-Web; SSE;
ALPN.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| HTTP/1.1 keep-alive | Yes | Yes | Yes | Yes | Yes | Yes |
| HTTP/2 (multiplex, HPACK) | Yes | Yes (≥2.4.17) | Yes | Yes (≥2.0) | Yes | Yes |
| h2c (cleartext h2) | Yes | Yes | Yes | Yes | Yes | Yes |
| HTTP/2 Server Push *(dead)* | No (rm 1.25.1) | Partial (dead) | No | No | No | No |
| HTTP/3 / QUIC | Yes (≥1.25.0) | **No** (not in 2.4.x) | Yes (default) | Partial (prod 2.7+) | Yes (≥1.22) | Yes (v3) |
| 0-RTT | Yes | No | Yes | Yes | Yes | Partial |
| WebSocket | Yes | Yes (mod_proxy_wstunnel) | Yes | Yes | Yes | Yes |
| gRPC proxying | Yes (≥1.13.10) | Yes | Yes | Yes (≥1.9.2) | Yes (reference) | Yes |
| gRPC-Web | No | No | No | No | **Yes** | **Yes** |
| SSE | Yes | Yes | Yes | Yes | Yes | Yes |

*Table-stakes:* HTTP/1.1, HTTP/2 (+HPACK/ALPN), WebSocket, SSE, basic gRPC proxy. *Advanced:* HTTP/3+QUIC
(+0-RTT), gRPC-Web. *Dead/avoid:* Server Push, h1 pipelining. *App-server baseline:* h1/h2/WS/SSE
everywhere; HTTP/3 & gRPC-Web opt-in.

## 2. TLS / transport security
**Expected:** TLS 1.2 (floor) & 1.3; 0-RTT early data (replayable — pair with RFC 8470 `425 Too Early`);
ALPN & SNI (+wildcard/multi-cert); **ECH** (new); **OCSP stapling — now legacy** (LE dropped OCSP Aug
2025); mTLS client-cert verify (+CRL); ACME/auto-HTTPS (HTTP-01/DNS-01/TLS-ALPN-01) + on-demand TLS;
cert hot-reload; session resumption (IDs+tickets); cipher control; HSTS.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| TLS 1.2 / 1.3 | Yes | Yes (≥2.4.43) | Yes | Yes | Yes | Yes |
| 0-RTT early data | Yes | No (native) | Yes | Yes | Yes | Partial |
| SNI + wildcard/multi-cert | Yes | Yes | Yes | Yes | Yes | Yes |
| ECH | Yes (≥1.29.4) | No | Partial (exp.) | No | No | No |
| OCSP stapling *(legacy)* | Yes | Yes | Yes (auto) | Yes | Yes | Partial |
| mTLS / client-cert verify | Yes | Yes | Yes | Yes (+CRL) | Yes | Yes |
| **ACME / auto-HTTPS** | **No** (ext agent) | Yes (mod_md) | **Yes (default)** | **No** (ext) | **No** (ext) | **Yes (built-in)** |
| On-demand TLS | No | No | **Yes** | No | No | Partial |
| Cert hot-reload | Yes (SIGHUP) | Yes (graceful) | Yes (auto) | Yes (Runtime API) | **Yes (SDS push)** | Yes (auto) |
| Session resumption | Yes | Yes | Yes | Yes | Yes | Yes |
| HSTS | Yes | Yes | Yes | Yes | Yes | Yes |

*Table-stakes:* TLS 1.2/1.3, SNI+multi-cert, mTLS, resumption, cipher control, HSTS, cert reload.
*Differentiators:* built-in ACME (Caddy default + dual-CA; Traefik; Apache mod_md — vs external agent
for nginx/HAProxy/Envoy), on-demand TLS (Caddy), SDS push (Envoy), ECH. *Fading:* OCSP stapling.
*App-server note:* TLS/ALPN/SNI/mTLS/resumption are library baseline (Go `crypto/tls`, rustls,
swift-nio-ssl); **ACME/OCSP/on-demand/hot-reload are NOT built-in — delegated to a fronting proxy** —
exactly why Caddy/Traefik exist.

## 3. Routing & request handling
**Expected:** path (prefix/exact/longest-match); regex; wildcard/glob; host/vhost; SNI routing;
method; header/query/cookie matching; content negotiation (`Accept`/`Accept-Language`) + `Vary`;
redirects (301/302/307/308) + internal/external rewrites + URL canonicalization; path params/named
captures; route precedence; expression language (CEL/ap_expr/ACL).

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Path prefix/exact, precedence | Yes | Yes | Yes | Yes | Yes | Yes |
| Regex routing | Yes | Yes | Yes | Yes | Yes (RE2) | Yes |
| Host / vhost | Yes | Yes | Yes | Yes | Yes | Yes |
| SNI routing | Yes (ssl_preread) | Yes | Partial | Yes | Yes | Yes (HostSNI, TCP) |
| Method / header / query / cookie | Yes | Yes | Yes | Yes | Yes | Yes |
| Content negotiation (Accept-Language) | No | **Yes (mod_negotiation)** | No | No | No | No |
| Redirects + rewrites + canonicalization | Yes | Yes | Yes | Yes | Yes | Partial |
| Path params / named captures | regex caps | regex caps | regex caps | regex caps | **Yes (uri_template)** | regex caps |
| Expression language | Partial | Yes (ap_expr) | Yes (CEL) | Yes (ACL) | Yes (CEL) | Yes |

*Table-stakes:* path+host+method+header/query matching with precedence, redirects, internal rewrites.
*Advanced:* regex (universal among proxies), SNI routing, true content negotiation (≈Apache-only),
first-class path params in a proxy (≈Envoy-only), expression languages. *App-server baseline:* named
path params (`:id`/`{id}`) + catch-all are standard (Go 1.22+, chi, Express, Fastify, axum, Hummingbird,
Vapor).

## 4. Reverse proxy / load balancing *(edge class — app servers sit behind this)*
**Expected:** upstream pools; DNS/Consul/k8s discovery; LB algorithms (RR, least-conn, IP/source hash,
EWMA/P2C least-request, random, weighted, consistent-hash/Maglev); active+passive health checks; retries
/ retry budgets / timeouts / hedging; circuit breaking / outlier detection; upstream keepalive pooling;
h2/h3 to upstream; sticky sessions; buffering; PROXY protocol v1/v2; gRPC/FastCGI/uwsgi/SCGI backends;
traffic splitting / canary; mirroring/shadowing.

| Feature (selected) | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Upstream pools | Yes | Yes | Yes | Yes | Yes | Yes |
| RR / least-conn / IP-hash | Yes | Partial | Yes | Yes | Yes | Partial |
| Consistent hash / Maglev | ketama | No | HRW | consistent | **ring+Maglev** | hrw |
| Active health checks | **Plus-only** | Yes | Yes | Yes | Yes | Yes |
| Circuit breaking / outlier detection | Partial | Partial | Partial | Partial | **Yes (full)** | Partial |
| Retry budgets / hedging | No | No | No | No | **Yes** | No |
| Sticky sessions (cookie) | **Plus-only** | Yes | Yes | Yes | Yes | Yes |
| PROXY protocol v2 | recv | recv | send+recv | **send+recv** | send+recv | recv |
| Consul / k8s discovery | No | No | No | Consul | EDS/xDS | **native** |

*Table-stakes (proxies):* pools, RR/least-conn/IP-hash, weighted, passive health, basic retries,
timeouts, keepalive, buffering, FastCGI. *Advanced (often commercial / LB-first):* active health checks
(nginx Plus), circuit breaking + outlier detection (Envoy/HAProxy), retry budgets + hedging (Envoy),
consistent-hash/Maglev, P2C, cookie stickiness (nginx Plus), h2/h3 upstream, PROXY v2 TLVs, SRV/Consul/k8s
discovery, splitting, mirroring. **App-server frameworks provide none of this — by design.**

## 5. Static file serving
**Expected:** Range (+multi-range) + `Accept-Ranges`; conditional GET (ETag/Last-Modified → 304);
directory index/autoindex; sendfile zero-copy + mmap; precompressed sidecar (`.gz`/`.br`/`.zst`);
byte-range cache slicing; `try_files` fallback.

| Feature | nginx | Apache | Caddy | (HAProxy/Envoy/Traefik) |
|---|---|---|---|---|
| Range / conditional / ETag | Yes | Yes | Yes | n/a (proxies don't serve a docroot) |
| Index + autoindex | Yes | Yes | Yes | No |
| sendfile zero-copy | Yes | Yes | Yes (Go) | n/a |
| Precompressed br sidecar | Module | Partial | **Yes** | No |
| Byte-range cache slicing | Module (slice) | No | No | No |
| try_files fallback | Yes | Partial | Yes | No |

*Table-stakes (static servers):* range + conditional + index + sendfile + MIME. *Advanced:* precompressed
brotli sidecar (built-in only Caddy), byte-range slice caching (nginx-only). *App-server note:* Go/Node/
Rust/Swift ship static handlers with range+conditional+ETag (e.g. Go `http.ServeContent`).

## 6. Caching
**Expected:** proxy/response cache; Cache-Control/Expires + revalidation (`stale-while-revalidate`,
`stale-if-error`, RFC 5861); custom keys; purge/invalidation; cache lock / request coalescing;
microcaching.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Proxy/content cache (built-in) | **Yes** | **Yes** | No (Souin plugin) | Yes (small RAM) | Experimental | No (plugin) |
| stale-while-revalidate | Yes | Partial | Plugin | No | Partial | Plugin |
| Cache lock / coalescing | Yes | Yes | Plugin | No | No | Plugin |
| Purge API | Plus/3rd-party | htcacheclean | Plugin | No | Limited | Plugin |

*Table-stakes (caching proxy):* Cache-Control/Expires honoring, TTL, Vary (nginx & Apache full; HAProxy/
Envoy basic). *Advanced:* stale-while-revalidate + bg update, coalescing, slice caching, purge —
strongest in **nginx**. *Note:* Caddy/Traefik have **no built-in content cache** (Souin plugin).

## 7. Compression
**Expected:** gzip / brotli / zstd / deflate response compression; precompressed vs on-the-fly; request
decompression; content-type filter; min-length; level.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| gzip on-the-fly | Yes | Yes | Yes | Yes | Yes | Yes |
| brotli on-the-fly | **Module** | Yes (≥2.4.26) | **Module** | No | Yes | Yes |
| zstd on-the-fly | Module (3rd-party) | No | Yes | No | Yes | Yes |
| Precompressed sidecar | Module | Partial | Yes | No | No | No |
| Request decompression | No | No | No | Partial | **Yes** | No |

*Table-stakes:* on-the-fly gzip + `Vary` + type filter + min-length. *Advanced:* on-the-fly brotli
(built-in Apache/Envoy/Traefik; module nginx/Caddy), zstd (built-in Caddy/Envoy/Traefik), request
decompression (Envoy). *Gotchas:* **nginx brotli is 3rd-party** (gzip-only built-in); **Caddy serves
precompressed brotli but can't brotli-encode on the fly** without a module. *App-server note:* Go has no
built-in response compression (middleware); Node/Rust/Swift add it via middleware.

## 8. Content & body handling
**Expected:** chunked (req+resp); trailers; multipart; body size limits; `Expect: 100-continue`;
buffering vs streaming both paths; streaming proxy; body rewriting.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Chunked req+resp | Yes | Yes | Yes | Yes | Yes | Yes |
| HTTP trailers | Passed | Passed | Yes | Passed | **First-class** | Passed |
| Body size limit | Yes | Yes | Yes | Partial | Yes | Yes |
| Expect: 100-continue | Yes | Yes | Yes | Yes | Yes | Yes |
| Streaming proxy (no full buffer) | Yes | Partial | Yes | Yes (default) | Yes (default) | Yes |
| Response body rewriting | Yes (sub_filter) | Yes (mod_substitute) | Partial | No | Yes (Lua/Wasm) | No |

*Table-stakes:* chunked req+resp, body size limit, `Expect: 100-continue`, basic streaming. *Advanced:*
correct trailer transport (Envoy first-class; gRPC needs end-to-end h2), buffering control (nginx most
granular), body rewriting, request decompression. *Note:* HAProxy/Envoy stream by default; nginx/Apache
buffer by default. **Multipart parsing is delegated to the app tier** — and IS table-stakes for app
frameworks (Go `ParseMultipartForm`, Node multer, Rust multipart, Swift MultipartKit).

## 9. Auth
**Expected:** Basic/Digest; JWT (sig/claims/JWKS); OAuth2/OIDC (forward-auth/subrequest); API keys;
mTLS→identity; external/forward auth (the universal delegation escape hatch).

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Basic auth | Yes | Yes | Yes | Yes | Yes | Yes |
| JWT (sig/claims/JWKS) | **Plus-only** | 3rd-party | Plugin | **Yes (≥2.5)** | **Yes (native)** | Hub / OSS plugin |
| OAuth2 / OIDC | njs/Plus | mod_auth_openidc | Plugin | SPOE/forward | ext_authz | Hub / ForwardAuth |
| mTLS → identity | Yes | Yes | Yes | Yes | Yes (+RBAC) | Yes |
| External / forward auth | Yes (auth_request) | Partial | Yes | Yes (SPOE) | **Yes (ext_authz)** | Yes (ForwardAuth) |

*Table-stakes:* Basic auth, mTLS verify, **external/forward auth** (the "delegate to an external service"
escape hatch — why missing native features rarely block adoption). *Advanced (clearest commercial line):*
native JWT/JWKS + OIDC + RBAC — **nginx gates JWT behind Plus**, **Traefik behind Hub**, while **Envoy**
and **HAProxy** ship it OSS. *App-server note:* Basic + JWT-verify (via libs) are baseline; OAuth2/OIDC
& mTLS offloaded.

## 10. Rate limiting / traffic control
**Expected:** request rate limit (bucket/sliding-window, per-key, distributed); connection limit; size
limits; timeouts (read/write/idle/header); Slowloris/slow-POST; backpressure / load shedding / adaptive
concurrency; bandwidth throttle.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Request rate limit (per-key) | Yes (limit_req) | mod_qos | **Plugin** | Yes (stick-tables) | Yes (local+global) | Yes |
| Distributed / cluster-wide | **Plus-only** | No | Plugin | Yes (peers) | **Yes (global RLS)** | Yes (Redis) |
| Connection limit | Yes (limit_conn) | Partial | No | Yes (maxconn) | Yes | Yes |
| Timeouts (read/write/idle/header) | Yes | Yes (+reqtimeout) | Yes | Yes | Yes | Yes |
| Slowloris protection | Yes | Yes (mod_reqtimeout) | Partial | Yes | Yes | Partial |
| Adaptive concurrency / load shedding | Partial | Partial | No | Partial | **Yes (Overload Mgr)** | Partial |

*Table-stakes:* timeouts, body/header size limits, basic Slowloris. Basic per-IP rate limiting is
table-stakes for proxies — but **NOT in default Caddy** (needs `caddy-ratelimit`) or **Apache** (needs
`mod_qos`; core `mod_ratelimit` is bandwidth-only). *Advanced:* distributed rate limit (Envoy global,
HAProxy peers, Traefik+Redis; nginx Plus-only), adaptive concurrency / overload manager (≈Envoy-only).

## 11. Observability
**Expected:** access logs (custom/JSON/conditional); leveled error logs; metrics (Prometheus/statsd);
tracing (OTel/W3C trace-context); self health/readiness; request-ID injection.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Access logs (custom) | Yes | Yes | Yes | Yes | Yes | Yes |
| Structured JSON logs | Partial | Partial | **Yes (default)** | Partial | Yes | Yes |
| **Prometheus metrics** | exporter/Plus | exporter | **native** | **native (PROMEX)** | **native** | **native** |
| Distributed tracing (OTel) | Yes (≥1.25.3) | Module | Yes (≥2.5) | SPOA/native | **Yes** | **Yes** |
| Self readiness endpoint | No | mod_status | admin API | Yes (monitor-uri) | **Yes (/ready)** | **Yes (/ping)** |
| Request-ID injection | Yes | Yes (unique_id) | Yes | Yes | Yes | Yes |

*Table-stakes:* access + leveled error logs + request-ID. *Modern/advanced:* native Prometheus endpoint
(Caddy/HAProxy/Envoy/Traefik) vs scrape-a-status-page + exporter (nginx/Apache); native OTel + W3C
trace-context (Envoy/Traefik/Caddy; nginx only recently); JSON-by-default (Caddy); real readiness
endpoint (Envoy/Traefik). **Envoy & Traefik are observability-natively complete; nginx/Apache push the
advanced surface to exporters/modules/paid tiers.** *App-server note:* via libraries (Go slog+OTel+
promhttp, Node pino/prom-client, Rust tracing+metrics, Swift swift-log/-metrics/-distributed-tracing).

## 12. Config & ops
**Expected:** hot reload (zero-downtime); graceful shutdown/draining; config format; process model;
dynamic config via API / discovery / k8s Ingress + Gateway API.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Hot reload (zero-downtime) | Yes (SIGHUP) | Yes (graceful) | Yes (API, rollback) | **Yes (hitless FD transfer)** | Yes (hot restart + xDS) | Yes (provider watch) |
| Graceful shutdown / drain | Yes | Yes | Yes | Yes | Yes | Yes |
| Dynamic API / discovery | **Plus-only** | No | Yes (admin API) | Yes (Runtime/Data Plane) | **Yes (xDS)** | Yes (providers) |
| k8s Ingress / Gateway API | Yes | No | Plugin | Yes | Yes | **Yes (Ingress+CRD+Gateway)** |

*Table-stakes:* graceful reload + graceful shutdown/drain + declarative config (universal). *Advanced:*
truly *hitless* socket-preserving reload (HAProxy FD passing, Envoy hot restart); dynamic control plane
(Envoy xDS, HAProxy/Caddy APIs; nginx Plus-only); Gateway API conformance. *App-server note:* graceful
shutdown is baseline (Go `Server.Shutdown`, Node, axum/actix, Hummingbird/Vapor); hitless reload + xDS
delegated to a fronting proxy.

## 13. Security hardening
**Expected:** security response headers (HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/
Permissions-Policy); CORS; smuggling defenses (TE/CL reject, strict parse); header count/size + URI
limits; DoS (HTTP/2 Rapid Reset, Settings/Ping/RST floods, CONTINUATION flood, max concurrent streams);
WAF (ModSecurity / Coraza / OWASP CRS); IP allow/deny + GeoIP; bot mitigation.

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Manage security headers | Yes | Yes | Yes | Yes | Yes | Yes |
| Native CORS | Partial | Partial | **Yes** | Partial | **Yes** | **Yes** |
| Smuggling defense (TE/CL reject) | Yes | Yes (Strict) | Yes | Yes | Yes (strict codec) | Yes |
| Max concurrent streams (h2) | Yes | Yes | Yes | Yes | Yes | Partial |
| Rapid Reset (CVE-2023-44487) | Yes | Yes (nghttp2 ≥1.57) | Yes (Go ≥1.21.3) | **Immune since 1.9** | Yes (PR #30055) | Yes (Go) |
| CONTINUATION flood (2024) | Not vuln | Yes (2.4.59) | Yes (Go) | Yes | Yes (1.29.3+) | Yes (Go) |
| WAF / OWASP CRS | Module (Coraza exp.) | **Native (mod_security2)** | Plugin (Coraza) | Plugin (Coraza) | Filter (Coraza Wasm) | Plugin / Hub |
| IP allow/deny + GeoIP | core + module | core + module | remote_ip + plugin | ACL + MaxMind | RBAC/CIDR + GeoIP | ipAllowList + plugin |

### HTTP/2 Rapid Reset (CVE-2023-44487) — per-server
Attack: open stream → immediate `RST_STREAM`; cancelled streams stop counting against
`MAX_CONCURRENT_STREAMS` while server work continues. Disclosed 2023-10-10 (CVSS 7.5).

| Server | Status | Fix |
|---|---|---|
| nginx | Default-safe | `keepalive_requests` 1000 + `http2_max_concurrent_streams` 128 bound it |
| Apache (mod_http2) | Affected | upgrade `libnghttp2` ≥ 1.57.0 |
| Caddy | Affected (Go) | rebuild on Go 1.21.3/1.20.10 (CVE-2023-39325) |
| **HAProxy** | **NOT affected** | stream-accounting fix shipped 1.9 (2018); validated to 800k rps under attack |
| Envoy | Affected | PR #30055 + Overload Manager + abusive-reset detection |
| Traefik | Affected (Go) | Go ≥1.21.3/1.20.10 |

**CONTINUATION flood (2024, CERT VU#421644)** is a distinct class (unbounded `CONTINUATION` w/o
`END_HEADERS` → OOM/CPU, often no access-log entry): Apache CVE-2024-27316 (→2.4.59), Envoy
CVE-2024-27919/-30255 (→1.29.3), Go/Caddy/Traefik CVE-2023-45288 (→Go 1.21.9/1.22.2). **nginx reported
NOT vulnerable.**

*Table-stakes (mostly core):* header manage; smuggling-resistant parsing; header/size/URI/body limits;
h2 `MAX_CONCURRENT_STREAMS`; Rapid-Reset + CONTINUATION patched; IP allow/deny. *Advanced:* typed
security-header bundles + native CORS (Caddy/Envoy/Traefik lead; nginx/Apache/HAProxy manual); WAF +
OWASP CRS (native only Apache/ModSecurity; others via Coraza plugin/filter or commercial); GeoIP; h2
frame-flood overload management (Envoy explicit); bot mitigation (largely commercial). *App-server note:*
CORS is table-stakes middleware; security headers via middleware; WAF is not an app-framework concern.

## 14. Extensibility
**Expected:** module/plugin systems; middleware chains; scripting (Lua/njs/Wasm); custom filters;
library embeddability vs daemon; external processing (ext_authz / ext_proc).

| Feature | nginx | Apache | Caddy | HAProxy | Envoy | Traefik |
|---|---|---|---|---|---|---|
| Dynamic/loadable modules | Yes (ABI-pinned) | **Yes (DSO/APXS)** | Partial (xcaddy) | No (compile-time) | Partial (Wasm dyn.) | Yes (Yaegi/Wasm) |
| Plugin catalog | No | No | Yes | No | No | **Yes (100+)** |
| Middleware / filter chain | Yes | Yes | Yes | Yes | Yes | Yes |
| Lua / njs scripting | OpenResty / **njs** | mod_lua | No | native Lua | Lua filter | No |
| Wasm extensions | No | No | Partial | No | **Yes (proxy-wasm)** | **Yes (http-wasm)** |
| External processing (ext_proc) | No | No | No | SPOE (partial) | **Yes (ext_proc)** | No |
| Embeddable as library | No | No | **Yes (Go)** | No | No | Partial |

*Table-stakes:* an extension mechanism + custom transform + middleware chain (the **primary model for app
frameworks**) + basic external-authz. *Advanced:* stable-ABI runtime modules (Apache DSO gold standard),
scripting (njs unique to nginx), **Wasm plugins** (Envoy/Traefik lead — the safer modern path), plugin
catalog (Traefik unique), out-of-process `ext_proc` body mutation (Envoy unique), **library
embeddability** (defining strength of Go/Rust/Swift frameworks vs the daemon model of nginx/Apache/
HAProxy/Envoy).

---

## Cross-cutting: what "production-grade" means
**Universal table-stakes:** h1/h2/WS/SSE · TLS 1.2/1.3 + SNI + mTLS + resumption + HSTS + cert reload ·
path/host/method/header/query routing + redirects + rewrites · (proxies) pools + RR/least-conn/IP-hash +
passive health + retries + timeouts + keepalive · (static) range + conditional/ETag + index + sendfile ·
on-the-fly gzip · chunked + body limits + `Expect: 100-continue` · Basic auth + forward-auth · timeouts +
size limits + Slowloris · access + error logs + request-ID · graceful reload + shutdown + declarative
config · smuggling-resistant parsing + Rapid-Reset/CONTINUATION patched + IP allow/deny · a middleware
mechanism.

**Differentiators:** HTTP/3+QUIC (+0-RTT) · gRPC-Web · built-in ACME + on-demand TLS + SDS rotation + ECH
· content negotiation · active health + circuit breaking + retry budgets + hedging + Maglev · brotli/zstd
+ request decompression · proxy cache + stale-while-revalidate + coalescing · native JWT/JWKS + OIDC +
RBAC · distributed rate limit + adaptive concurrency · native Prometheus + native OTel + readiness ·
hitless reload + xDS + Gateway API · WAF/OWASP-CRS · Wasm plugins + ext_proc + library embeddability.

---

## Sources

Local inspection: `nginx -V` (1.31.2), `caddy list-modules`+`version` (v2.11.4, 133 modules), `httpd -V`+`-l` (2.4.66 prefork).

Protocols/TLS — nginx QUIC https://nginx.org/en/docs/quic.html · http_v3 https://nginx.org/en/docs/http/ngx_http_v3_module.html · Push removal https://trac.nginx.org/nginx/ticket/2432 · ECH https://blog.nginx.org/blog/encrypted-client-hello-comes-to-nginx · Apache mod_http2 https://httpd.apache.org/docs/2.4/mod/mod_http2.html · mod_md https://httpd.apache.org/docs/2.4/mod/mod_md.html · Caddy auto-HTTPS https://caddyserver.com/docs/automatic-https · HAProxy QUIC https://www.haproxy.com/blog/how-to-enable-quic-load-balancing-on-haproxy · Envoy TLS https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl · SDS https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret · Traefik v3 https://traefik.io/blog/announcing-traefik-proxy-v3-rc · ACME https://doc.traefik.io/traefik/https/acme/ · Chrome Push removal https://developer.chrome.com/blog/removing-push · ECH/Cloudflare https://blog.cloudflare.com/encrypted-client-hello/ · RFC 9849 https://datatracker.ietf.org/doc/rfc9849/ · LE ending OCSP https://letsencrypt.org/2024/12/05/ending-ocsp · RFC 8470 https://datatracker.ietf.org/doc/html/rfc8470 · 0-RTT replay https://blog.trailofbits.com/2019/03/25/what-application-developers-need-to-know-about-tls-early-data-0rtt/

Routing/Proxy/LB — nginx location https://nginx.org/en/docs/http/ngx_http_core_module.html#location · ssl_preread https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html · upstream https://nginx.org/en/docs/http/ngx_http_upstream_module.html · Plus health checks https://docs.nginx.com/nginx/admin-guide/load-balancer/http-health-check/ · Apache mod_negotiation https://httpd.apache.org/docs/2.4/mod/mod_negotiation.html · mod_proxy_balancer https://httpd.apache.org/docs/2.4/mod/mod_proxy_balancer.html · mod_proxy_hcheck https://httpd.apache.org/docs/2.4/mod/mod_proxy_hcheck.html · Caddy matchers https://caddyserver.com/docs/caddyfile/matchers · reverse_proxy https://caddyserver.com/docs/caddyfile/directives/reverse_proxy · HAProxy ACLs https://www.haproxy.com/documentation/haproxy-configuration-tutorials/core-concepts/acls/ · health checks https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/ · PROXY protocol https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/client-ip-preservation/enable-proxy-protocol/ · Envoy route https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto · outlier detection https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/outlier · LB https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers · Traefik routing https://doc.traefik.io/traefik/reference/routing-configuration/http/routing/rules-and-priority/ · app routers: Go ServeMux https://pkg.go.dev/net/http#ServeMux · chi https://github.com/go-chi/chi · Express https://expressjs.com/en/guide/routing.html · Fastify https://fastify.dev/docs/latest/Reference/Routes/ · axum https://docs.rs/axum/latest/axum/struct.Router.html · Hummingbird https://docs.hummingbird.codes/2.0/documentation/hummingbird/routerguide/ · Vapor https://docs.vapor.codes/basics/routing/

Static/Cache/Compression/Body — nginx proxy https://nginx.org/en/docs/http/ngx_http_proxy_module.html · slice https://nginx.org/en/docs/http/ngx_http_slice_module.html · caching guide https://blog.nginx.org/blog/nginx-caching-guide · brotli https://github.com/google/ngx_brotli · Apache mod_brotli https://httpd.apache.org/docs/2.4/mod/mod_brotli.html · mod_cache https://httpd.apache.org/docs/current/mod/mod_cache.html · Caddy encode https://caddyserver.com/docs/caddyfile/directives/encode · file_server https://caddyserver.com/docs/caddyfile/directives/file_server · caddy-cbrotli https://github.com/dunglas/caddy-cbrotli · HAProxy compression https://www.haproxy.com/documentation/haproxy-configuration-tutorials/performance/compression/ · Envoy compressor https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter · decompressor https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/decompressor_filter · Souin https://docs.souin.io/

Auth/Rate-limit/Observability/Ops — nginx auth_request https://nginx.org/en/docs/http/ngx_http_auth_request_module.html · limit_req https://nginx.org/en/docs/http/ngx_http_limit_req_module.html · otel https://nginx.org/en/docs/ngx_otel_module.html · JWT (Plus) https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-jwt-authentication/ · Apache mod_auth_openidc https://github.com/OpenIDC/mod_auth_openidc · mod_qos http://mod-qos.sourceforge.net/ · Caddy forward_auth https://caddyserver.com/docs/caddyfile/directives/forward_auth · caddy-ratelimit https://github.com/mholt/caddy-ratelimit · metrics https://caddyserver.com/docs/metrics · HAProxy JWT https://www.haproxy.com/blog/verify-oauth-jwt-tokens-with-haproxy · PROMEX https://github.com/haproxy/haproxy/blob/master/addons/promex/README · hitless reloads https://www.haproxy.com/blog/hitless-reloads-with-haproxy-howto · Envoy jwt_authn https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter · ext_authz https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter · adaptive_concurrency https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/adaptive_concurrency_filter · overload manager https://www.envoyproxy.io/docs/envoy/latest/configuration/operations/overload_manager/overload_manager · hot restart https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart · Traefik forwardauth https://doc.traefik.io/traefik/middlewares/http/forwardauth/ · ratelimit https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/ · tracing https://doc.traefik.io/traefik/observe/tracing/ · Go Shutdown https://pkg.go.dev/net/http#Server.Shutdown · Gateway API https://gateway-api.sigs.k8s.io/implementations/

Security/Extensibility — CVE-2023-44487 NVD https://nvd.nist.gov/vuln/detail/cve-2023-44487 · CISA https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487 · HAProxy not-affected https://www.haproxy.com/blog/haproxy-is-not-affected-by-the-http-2-rapid-reset-attack-cve-2023-44487 · Envoy PR #30055 https://github.com/envoyproxy/envoy/pull/30055 · Go 1.21.3 advisory https://groups.google.com/g/golang-announce/c/iNNxDTCjZvo · CERT VU#421644 https://kb.cert.org/vuls/id/421644 · Coraza https://www.coraza.io/docs/tutorials/introduction/ · xcaddy https://github.com/caddyserver/xcaddy · Traefik Wasm https://traefik.io/blog/traefik-3-deep-dive-into-wasm-support-with-coraza-waf-plugin · Envoy ext_proc https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter
