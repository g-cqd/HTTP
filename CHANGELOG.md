# Changelog

## Unreleased — deep security hardening (2026-06-25)

A second-pass adversarial hardening of the stack; see
`Documentation/audit/2026-06-25-deep-hardening-audit.md` and `Documentation/Security.md`.

### Breaking
- **`HTTPLimits` default ceilings lowered.** `maxConnections` → 65 536, `maxConnectionsPerClient` →
  1 024 (were 1 048 576). Restore the permissive ceilings with `HTTPLimits.highThroughput`, or tighten
  further with `HTTPLimits.hardened`. `maxConcurrentStreams` remains a bounded 128.
- **`SetCookie.headerValue` is now `String?`** — `nil` for an invalid cookie (fail-closed
  serialization). Callers must unwrap.
- **`CORSMiddleware(allowedOrigin: .any, allowCredentials: true)` no longer reflects credentials** — a
  wildcard origin is always credential-free. Use `.allowList([...])` for credentialed multi-origin CORS.
- **`WebSocketHandler.isOriginAllowed` defaults to deny browser origins** (admits only a request with no
  `Origin`). Override / allowlist to admit specific origins.

### Added
- Routing result-builder DSL: `Router`, `Route`, `RouteBuilder`, `RouteParameters` (method + `:param`
  path matching, 404/405).
- `ServerResponse.text(_:status:)` / `.json(_:status:)` / `.status(_:)`.
- `HTTPLimits.highThroughput` and `HTTPLimits.hardened` presets, and `maxControlFramesPerInterval`.
- `Expect: 100-continue` handling (interim `100`, or `417` for an unsupported expectation).
- `HTTPFieldName.expect`, `HTTPStatus.expectationFailed`.
- Observability seam: the `HTTPMetrics` protocol + `MetricsMiddleware` record one per-response metric
  (method, path, status, monotonic duration). Dependency-free — bridge it to swift-metrics /
  swift-distributed-tracing downstream; costs nothing when not installed.

### Fixed (security)
- **HTTP/2 DoS:** charge server-emitted `REFUSED_STREAM` and the zero-length-DATA / PRIORITY /
  `WINDOW_UPDATE`-on-closed / SETTINGS-ACK floods; split the reset vs control-frame budgets
  (CVE-2025-8671, CVE-2023-44487, CVE-2019-9513, CVE-2019-9518).
- **HTTP/2 DoS (memory):** bound the cross-stream sum of un-dispatched request body per connection — the
  receive window replenishes during buffering, so the per-stream `maxBodySize` cap alone allowed up to
  `maxConcurrentStreams × maxBodySize`; the body is released on dispatch so pipelining is unaffected
  (CWE-400/770).
- **HTTP/1.1 DoS:** bound a CRLF-less chunk-size / chunk-ext / trailer line (CWE-400/770).
- **WebSocket:** secure-by-default `Origin` (CWE-346/1385); incremental UTF-8 validation across
  fragments (RFC 6455 §8.1).
- **Cookies:** validate `Domain`/`Path` octets + `__Host-`/`__Secure-` prefix invariants (CWE-113).
- **CORS:** never pair a wildcard with credentials; emit `Vary: Origin` on a reflected origin (CWE-942).

### Changed
- Unified the HTTP/2 and HTTP/3 request mappers into one generic `HTTPCore.RequestMapper` — a single
  source of truth for the RFC 9113 §8.3 / RFC 9114 §4.3 pseudo-header + field validation.
