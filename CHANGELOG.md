# Changelog

## Unreleased — TOCTOU-safe static file serving (2026-07-31)

`FileResponder` resolved a request path by string (`resolvingSymlinksInPath()` + a `hasPrefix`
containment check) and then opened the result **by name**, repeatedly — `fileExists`,
`attributesOfItem`, `FileHandle(forReadingAtPath:)`, the streaming pump, the h1 `open()` before
`sendfile(2)`, and the `.br`/`.gz` sidecar lookup. A writer able to swap a path component between the
check and any of those opens escaped the root (CWE-367 time-of-check/time-of-use, CWE-59 link
following).

Resolution is now anchored on a descriptor: the root is opened once, each request component is one
`openat(2)` hop with `O_NOFOLLOW`, and the descriptor that is verified is the descriptor that is
stat'd, read, and handed to `sendfile(2)`. Containment is structural, so there is no window at all.

### Breaking
- **`ResponseBodyWriter.writeFile(atPath:offset:length:)` → `writeFile(_ region: FileRegion)`.** A
  pathname cannot express the invariant — the writer must not be able to perform a lookup. A conformer
  that overrode it gets `region.descriptor` / `.offset` / `.length`.
- **A symlink under the root is now refused (`403`)**, where the prefix check served an in-root one.
- **A file the process cannot open is `403`**, not `500`: resolution *is* the open, so `EACCES`
  surfaces where it happens (RFC 9110 §15.5.4).
- **A `FileResponder(root:)` whose root is not an existing directory answers `500`**, not `404` — that
  is a misconfiguration, not a missing resource.

### Added
- `RootDirectory`, `OpenedDirectory`, `OpenedFile`, `FileRegion`, and the `POSIXFile` syscall wrappers.
  `OpenedFile` exposes the verified `descriptor`, and the `size`/`modifiedAt` from **that
  descriptor's** `fstat` — so `Content-Length`, `ETag`, and `Last-Modified` cannot describe a file a
  concurrent rename swapped out.

### Fixed (security)
- **CWE-367 / CWE-59:** a rename racing static file serving can no longer leak a file outside the root.
- **A FIFO or device node under the root is refused** rather than opened. `FileManager.fileExists` +
  `FileHandle(forReadingAtPath:)` would open a FIFO, and `open(2)` on one with no writer blocks — the
  serve task parked forever. The lookup flags carry `O_NONBLOCK` and the leaf `fstat` requires
  `S_IFREG`.
- **The autoindex listing** is read from the verified directory descriptor (`fdopendir` + `fstatat`
  with `AT_SYMLINK_NOFOLLOW`) and lists only regular files and directories.

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
- RFC 8941 Structured Fields **codec** (`StructuredFields.parseItem` / `.parseList` / `.parseDictionary`
  and `.serialize(…)`) — all six bare-item types, parameters, and inner lists; fail-closed (typed
  `ParseError` / `SerializeError`), bounded, non-recursive. The substrate for Structured-Field headers.
- RFC 9218 `Priority`: `HTTPPriority` parses the field into a typed urgency/incremental pair (defaults
  for absent / out-of-range / unparseable input) and serializes back, omitting defaults;
  `HTTPRequest.priority` reads it. Adds the `HTTPFieldName.priority` registered name.

### Fixed (security)
- **HTTP/2 DoS:** charge server-emitted `REFUSED_STREAM` and the zero-length-DATA / PRIORITY /
  `WINDOW_UPDATE`-on-closed / SETTINGS-ACK floods; split the reset vs control-frame budgets
  (CVE-2025-8671, CVE-2023-44487, CVE-2019-9513, CVE-2019-9518).
- **HTTP/2 & HTTP/3 DoS (memory):** bound the cross-stream sum of un-dispatched request body per
  connection — the HTTP/2 receive window replenishes during buffering, so the per-stream `maxBodySize`
  cap alone allowed up to `maxConcurrentStreams × maxBodySize`; the body is released on dispatch so
  pipelining is unaffected. HTTP/3 carries the same bound (over-budget DATA → `H3_EXCESSIVE_LOAD`)
  (CWE-400/770).
- **HTTP/1.1 DoS:** bound a CRLF-less chunk-size / chunk-ext / trailer line (CWE-400/770).
- **WebSocket:** secure-by-default `Origin` (CWE-346/1385); incremental UTF-8 validation across
  fragments (RFC 6455 §8.1).
- **Cookies:** validate `Domain`/`Path` octets + `__Host-`/`__Secure-` prefix invariants (CWE-113).
- **CORS:** never pair a wildcard with credentials; emit `Vary: Origin` on a reflected origin (CWE-942).
- **TLS ALPN (ALPACA):** over TLS, refuse a connection that negotiated neither `h2` nor `http/1.1`
  (including no ALPN) instead of silently serving HTTP/1.1; `TransportConnection.isSecure` distinguishes
  TLS from cleartext, which is unaffected (RFC 7301 §3.2).
- **HTTP/3 trailers:** validate a trailing HEADERS block (no pseudo-header fields, lowercase names only,
  RFC 9114 §4.3/§4.2) — a malformed trailer is now `H3_MESSAGE_ERROR` instead of being silently accepted,
  matching the HTTP/2 path.

### Changed
- Unified the HTTP/2 and HTTP/3 request mappers into one generic `HTTPCore.RequestMapper` — a single
  source of truth for the RFC 9113 §8.3 / RFC 9114 §4.3 pseudo-header + field validation. Trailer
  validation is likewise shared (`RequestMapper.validateTrailers`), so both engines apply one rule.
