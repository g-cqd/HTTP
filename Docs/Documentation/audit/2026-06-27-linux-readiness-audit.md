# Linux-readiness audit (G0 prep) — 2026-06-27

Static survey of the **non-transport** codebase for Linux portability, performed on macOS (no Linux
toolchain needed to *inventory* the coupling). It closes the gap-closing roadmap's G0 "Foundation-usage
audit" and "Synchronization/atomics" items and serves as the checklist for the `POSIXEpoll` backbone work.

**Headline:** the codebase is **Linux-ready except the I/O floor.** Every shipping layer above the
transport — the sans-I/O engines, the server runtime, observability, auth, the TLS stack (vendored
BoringSSL, ADR 0004 Phase 6) — uses only Linux-available APIs. The **single blocker** is that no
transport backbone compiles on Linux: kqueue, Network.framework, and even the swift-system backbone
`import Darwin`. Writing the `POSIXEpoll` backbone (and verifying it on a Linux toolchain) is the
remaining G0 deliverable.

## Findings by area

| Area | Status | Detail |
|---|---|---|
| **Core `HTTPConcurrency`** | ✅ portable | The only core file touching the platform, `NowProvider.swift`, is already `#if canImport(Darwin) / #elseif canImport(Glibc)` guarded. |
| **Protocol engines** (HTTP1/2/3, HPACK, QPACK, WebSocket) | ✅ portable | Pure Swift, sans-I/O; no `Darwin`/`Network`/Foundation-quirk imports. |
| **Foundation usage** | ✅ Linux-available | ~27 files use Foundation, but only APIs swift-corelibs-foundation ships: `Data` (61×), `DispatchQueue` (20×, libdispatch on Linux), `Process`/`ProcessInfo` (in `DevTLSIdentity`, examples), `URL`, `FileManager` (3× in `FileResponder`), `JSONDecoder` (2×), one `NSLock`. No `NS*`-only or Darwin-only Foundation APIs. |
| **`Synchronization`** (Mutex/Atomic) | ✅ Swift 6 Linux | 34 files import `Synchronization`; 8 `Atomic<…>`, 15 `ContinuousClock`. All present in the Swift 6 Linux toolchain (fallback: swift-atomics if a floor pre-6.0 is ever needed). |
| **TLS** | ✅ portable | Vendored, symbol-prefixed BoringSSL (ADR 0004 Phase 6). The vendored tree already carries the Linux asm + the prefix symbols span mac/iOS/Linux. |
| **`DevTLSIdentity`** (test/dev identity) | ✅ portable | Generates the PKCS#12 by shelling out to the `openssl` CLI via Foundation `Process` — **not** Security.framework. `SecPKCS12Import` is only the *Network* backbone's consumer; the portable backbone parses the blob via BoringSSL. So the gated portable-TLS suite can run on Linux (needs `openssl` on `PATH`). |
| **Transport backbones (the I/O floor)** | ❌ **the gap** | `POSIXKqueue`, `Network`, `Quic`, `POSIXDispatch`, **and `SwiftSystem`** all `import Darwin`. No backbone compiles on Linux ⇒ `POSIXEpoll` is required. |
| **Examples** | ⚠️ trivial | `httpd-example/Prefork.swift` `import Darwin` (uses `fork()`); needs a `#elseif canImport(Glibc)` guard for the Linux example. Example-only, not the library. |

## Conclusion & the remaining G0 work

Once the **`POSIXEpoll` transport backbone** lands, the stack should come together on Linux with little
else: the engines, Foundation surface, Synchronization, TLS, and test fixtures are all already portable.
The epoll backbone is the structural mirror of `POSIXKqueue/KqueueEventLoop.swift` over the shared
`POSIXShared/POSIXSocket` plumbing (bind/listen, `SO_REUSEPORT` prefork, EINTR/EAGAIN, dual-stack — all
already written and portable), swapping the kqueue readiness mechanism for `epoll_create1` /
`epoll_ctl` / `epoll_wait`.

**It must be authored and verified on a Linux toolchain** (`epoll(7)` does not exist on Darwin, so it
cannot be compiled or tested on macOS — writing it blind would violate the project's verify-before-merge
discipline). Recommended landing order (per the gap-closing roadmap G0 gate): (a) `POSIXEpoll` + the
cleartext suite green on Linux, (b) portable TLS + h2/WS-over-TLS green on Linux (the vendored BoringSSL
is ready), (c) the `ubuntu-latest` CI job + the cross-platform support matrix. HTTP/3 stays Darwin-only
in v1 (QUIC is Network.framework-provided).

## Verification — 2026-06-28 (apple/container · Swift 6.5-dev / Ubuntu noble · aarch64)

The survey was validated on a real Linux toolchain: Apple's `container` runtime running the
`swiftlang/swift:nightly-noble` image (Swift 6.5-dev accepts the package's `swift-tools-version: 6.4`;
no stable `swift:6.4` image exists yet). Dependencies were seeded offline from the macOS-resolved
`.build/checkouts` (the lightweight-VM NAT throttles `git clone`, aborting on `http.lowSpeedLimit`), and
the build used a container-internal scratch path so the macOS `.build` was never clobbered. The VM was
given 8 GB RAM — a 1 GB default OOM-thrashes `swift-frontend` and wedges the runtime.

**Result: the whole library *and* `httpd-example` build on Linux, and the epoll backbone serves real
HTTP/1.1 end to end.** Running `httpd-example` on the Linux-default `posixEpoll` backbone answered
`GET /`, `GET /health`, `GET /hello/:name` (path parameters), and `POST /echo` (request body) with `200`s
and the full middleware chain (ETag, CORS, security headers, Date) — i.e. bind/accept/read/write over
`epoll(7)`, the ported `POSIXSocket`, the HTTP/1.1 engine, the `Router`, and middleware all working.

The survey's "Linux-ready except the I/O floor" was **optimistic**: beyond the transport, several
upper-layer couplings only surfaced once compiled for real. Each was fixed portably and re-validated by
the 950-test macOS suite (unchanged):

| Gap (found on first Linux compile) | Fix |
|---|---|
| `epoll(7)` absent from Swift's `Glibc` module (no `epoll_event` / `epoll_create1` / `EPOLL*`) | New `CEpoll` C shim re-exporting `<sys/epoll.h>`, depended on `.when(platforms: [.linux])`. |
| `POSIXSocket`: `SOCK_STREAM` imports as the `__socket_type` enum, `IPPROTO_TCP` as `Int` on Glibc | `Int32(SOCK_STREAM.rawValue)` (Linux branch); `Int32(IPPROTO_TCP)` (portable). |
| `epoll_wait` buffer pointer is non-optional on Linux; `send` shadowed by the instance method | `guard let base = buffer.baseAddress`; `Glibc.send(...)`. |
| `WebSocketHandshake` used CryptoKit (`Insecure.SHA1`) | Pure-Swift `SHA1` (FIPS 180-4) on both platforms; RFC 6455 §1.3 vector test passes. |
| `SessionMiddleware` used CryptoKit (`HMAC<SHA256>`) for signed cookies | Pure-Swift `SHA256` + `HMACSHA256` (RFC 2104), constant-time compare; both platforms. |
| `FileResponder` used `UniformTypeIdentifiers` (`UTType`) for MIME | Gated: `UTType` on Apple, a built-in web MIME table on Linux. |
| `Compression` framework (Brotli/gzip/inflate) is Apple-only | Gated `#if canImport(Compression)`; on Linux zstd (`CZstd`, `HTTP_ZSTD`) is the cross-platform coding. |

The Darwin/Network backbones (kqueue, Network.framework + QUIC, Dispatch, swift-system) are excluded from
the Linux build graph per-platform in `Package.swift`; the `TransportFactory` cases that name them are
guarded by matching `#if canImport(Darwin)` / `#if canImport(Network)`.

### Remaining G0 follow-ups (do not block the Linux build)
- **Linux test suite + CI:** the test target still has Darwin-only test files (Network/kqueue/QUIC
  backbone tests) to gate before `swift test` runs on Linux; then an `ubuntu-latest` CI job.
- **Vendored BoringSSL on Linux** (`HTTP_PORTABLE_TLS`): `PortableTLS*` still `import Darwin` and need a
  Darwin→Glibc port before the gated TLS suite runs on Linux (the vendored tree itself carries Linux asm).
- **Linux content codings:** gzip via the already-linked zlib and Brotli via `libbrotli`, so Linux gets
  gzip/br out (and inbound decoders), not only zstd.
