# ADR 0004 — Portable TLS backbone (the non-Network.framework TLS path)

- **Status:** Accepted (system-OpenSSL-first ratified 2026-06-27; Phase 1 shipped) — resolves **D1**
- **Context date:** 2026-06

## Context

Two pressures converge on one missing piece — a TLS stack that is **not** Network.framework:

1. **Linux (G0).** Servers run on Linux; the stack is Apple-only because Network.framework is. The
   sans-I/O engines are already portable; the gaps are the I/O floor (a `POSIXEpoll` backbone, modeled
   on the existing `KqueueEventLoop`) and a TLS path that exists off-Darwin.
2. **`.optional` client-auth + SNI multi-cert (W2 deferred).** Investigation (roadmap log 2026-06-26;
   commit `c0249df`) proved the *modern* `NetworkListener<TLS>` backbone **cannot** validate a
   presented client certificate on macOS 26 / SDK 27 — `Network.TLS.certificateValidator` is never
   invoked and the handshake deadlocks. And **no** Network.framework API (legacy or modern) exposes a
   server-side SNI server-name callback for per-name certificate selection. Both features need a real,
   controllable TLS stack.

The backbone must reach feature parity with the Network.framework backbone, because the sans-I/O
engines and the server runtime consume only the abstraction (`ServerTransport` /
`TransportConnection`), not a concrete backbone:

- ALPN (RFC 7301) with the strict-ALPN / ALPACA refusal (no `h2`/`http/1.1` ⇒ reject), surfaced as
  `TransportConnection.negotiatedApplicationProtocol` + `isSecure`.
- TLS version range pinned to 1.3 floor **and** ceiling (RFC 8446 / RFC 9325; audit T-F5).
- Client-auth `.none` / `.optional` / `.required` with a backbone-agnostic `verifyPeer` hook over the
  **DER chain, leaf-first** (the exact `TransportTLS` contract used today), and the verified leaf
  subject surfaced as `TransportConnection.tlsPeerSubject` → the server-asserted `.xClientCertSubject`
  header (G3).
- **SNI multi-cert selection** — pick the identity by the client's `server_name` (the G4 sub-gap).
- **Hot certificate reload** — `ServerTransport.reload(tls:)` parity (G4b).
- The CLAUDE.md non-negotiables: no SwiftNIO; no force-unwrap/cast; strict concurrency; fail-closed
  typed `TransportError`; the unsafe C interop bounded to one place (as `NetworkFrameworkTLS` does for
  the `sec_protocol_*` surface).

## Investigation (measurement)

**There is no apple/swiftlang-only source of `libssl` (the TLS handshake/record layer).**

- `swift-crypto`'s `CCryptoBoringSSL` is **libcrypto only**: its tree has `crypto/`, `gen/`,
  `third_party/` — **no `ssl/` directory**, and `grep -r SSL_CTX_new Sources/` across the checkout
  returns nothing. So roadmap option **(c)** ("swift-crypto's BoringSSL + a minimal TLS-record
  binding") does **not** mean "bind a few records" — it means **hand-writing the TLS 1.3 state
  machine** (handshake, key schedule, record protection, alerts) on top of raw primitives. That is an
  XXL effort and a standing security liability (every CVE class becomes ours). **Option (c) is
  rejected.**
- `swift-nio-ssl`'s `CNIOBoringSSL` *does* vend full BoringSSL (crypto + ssl) as NIO-free C, but the
  package is off the table per CLAUDE.md.
- System OpenSSL is present on this host (`/opt/homebrew/opt/openssl@3/lib/libssl.{a,dylib}` +
  headers) and is the standard Linux TLS library.

**The socket + accept machinery already exists and is reusable.** `POSIXSocket` (shared by the
kqueue/dispatch/swift-system backbones) already does `socket`/`bind`/`listen`, dual-stack IPv4/IPv6
via `getaddrinfo`, `SO_REUSEADDR`/`SO_REUSEPORT`, `SO_NOSIGPIPE` (audit T-F1), `TCP_NODELAY`,
non-blocking mode, `getpeername` resolution, `accept()`-error classification
(`EAGAIN`/`EINTR`/`EMFILE`/`EBADF` → `wouldBlock`/`retry`/`backoff`/`stop`), and a zero-fill-free
`readBuffer`. A TLS backbone is therefore **"TLS over an accepted fd"** — it owns no new socket
policy, only the SSL object layered on each accepted connection.

So the real fork is narrowed to **(a) vendor BoringSSL ourselves** vs **(b) link system OpenSSL** —
and the libssl binding is the only part that is provider-specific.

## Decision

Three parts:

### 1. Architecture: a provider seam, so "the TLS backbone" is decoupled from "which libssl"

Introduce a thin **`TLSProvider`** seam. The backbone (accept loop, async byte bridge, lifecycle,
abstraction conformance) is **provider-agnostic** and lives in Swift; the libssl calls live behind one
C shim + one Swift adapter implementing `TLSProvider`. This is the load-bearing decision: it makes the
provider (system OpenSSL now, vendored BoringSSL later) a **swappable detail**, not a rewrite, and
keeps the unsafe interop bounded to one file (the `NetworkFrameworkTLS` discipline).

    Sources/Transport/HTTPTransport/PortableTLS/
      PortableTLSTransport.swift     ServerTransport: accept loop (reuses POSIXSocket) → AsyncStream
      PortableTLSConnection.swift    TransportConnection: SSL_read/SSL_write bridged to async
      TLSProvider.swift              protocol: context, per-conn SSL object, handshake, I/O, metadata
      TLSContext.swift               ALPN/version/peer-auth/SNI config, value-typed, Sendable
      OpenSSLProvider.swift          TLSProvider over the C shim (the first concrete provider)
    Sources/Core/CHTTPBoringSSL/     C shim: the *only* place that #includes <openssl/ssl.h>
                                     (named for the eventual provider; OpenSSL is ABI-compatible here)

### 2. First provider: **system OpenSSL, gated and opt-in**; vendored BoringSSL is the follow-up

Build the full backbone against system OpenSSL first, because it delivers **working `.optional` + SNI
+ mTLS + Linux TLS now** and validates the entire architecture (the hard, reusable part) before
paying for vendoring. Quarantine the dependency:

- The `CHTTPBoringSSL` shim target and the OpenSSL link are **conditional on a build flag**
  (`HTTP_PORTABLE_TLS=1`, mirroring the existing env-driven `HTTP_WARNINGS_AS_ERRORS` manifest
  pattern). The **default build stays apple/swiftlang-only** — no OpenSSL in a downstream consumer's
  graph unless they opt in.
- `TransportFactory` only ever returns the portable backbone when explicitly selected
  (`TransportBackbone.portableTLS`) — never silently in place of `.networkFramework`.

**Vendored BoringSSL (option a) is the productionization path**, recorded here as a follow-up: it
drops in as a second `TLSProvider` behind the same seam (a `CHTTPBoringSSL` that vends real BoringSSL
sources instead of `-lssl` flags), with **zero changes** to `PortableTLS*` or the abstraction. It is
deferred because doing it correctly (hundreds of generated sources, per-arch asm, an upstream-tracking
vendoring script — the reason `swift-nio-ssl` exists) is multi-session and orthogonal to proving the
design.

> Ratification point: this ADR recommends **system-OpenSSL-first behind the seam**. The alternative —
> **vendor BoringSSL before any TLS runs** — is viable but XL up front; see *Alternatives*. The seam
> makes the choice low-regret either way.

### 3. Rejected: option (c) (hand-rolled TLS on libcrypto) and SwiftNIO — see *Investigation* / *Alternatives*.

## Architecture detail — how each requirement maps to the OpenSSL/BoringSSL API

The point of the seam is that these are **provider calls**; the mappings below hold for both OpenSSL
and BoringSSL (BoringSSL is API-compatible for this surface).

| Requirement | Binding |
|---|---|
| Identity from PKCS#12 | `d2i_PKCS12_bio` + `PKCS12_parse` → `EVP_PKEY` + leaf `X509` + CA stack → `SSL_CTX_use_certificate` / `SSL_CTX_use_PrivateKey` / `SSL_CTX_add1_chain_cert`. Reuses the existing `TransportTLS.pkcs12`/`passphrase` contract; **no keychain** (sidesteps the `SecPKCS12Import` pollution that `f1d4ba8` had to clean up). |
| ALPN + ALPACA | `SSL_CTX_set_alpn_select_cb` selects from the client's list against ours (RFC 7301); **no overlap ⇒ fail the handshake** (alert `no_application_protocol`), which *is* the strict-ALPN refusal — stronger than the Network path's post-accept check. |
| TLS 1.3 floor + ceiling | `SSL_CTX_set_min_proto_version(TLS1_3_VERSION)` + `set_max_proto_version` (RFC 9325; audit T-F5). |
| `.none` | `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, …)` — no CertificateRequest. |
| `.required` | `SSL_VERIFY_PEER` \| `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` — request **and** require; no-cert ⇒ handshake fails. |
| **`.optional`** | `SSL_VERIFY_PEER` **without** `FAIL_IF_NO_PEER_CERT` — request, proceed if absent. This is precisely the request-but-don't-require semantic the modern Network path was supposed to provide and instead deadlocked. OpenSSL implements it natively. |
| `verifyPeer` over DER | `SSL_CTX_set_cert_verify_callback` — invoked **once with the full chain** for a presented cert; we `i2d_X509` each (leaf-first), call the hook, return 1/0 (0 fails the handshake). Replaces default trust (the G3 "verify block is the policy; nil hook accepts any presented chain" semantic, ported verbatim). For `.optional` + no cert the callback isn't called → connection proceeds with `tlsPeerSubject == nil`. |
| `tlsPeerSubject` | leaf `X509_get_subject_name` → CN, captured at handshake completion (mirrors `NetworkFrameworkTLS.peerSubject`). |
| **SNI multi-cert** | one `SSL_CTX` per identity, keyed by server-name; `SSL_CTX_set_tlsext_servername_callback` reads `SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)` and `SSL_set_SSL_CTX(ssl, perHostCtx)`. The hook Network.framework lacks. `TransportTLS` grows an optional name→identity map (additive; single-identity callers unaffected). |
| Hot reload (G4b) | swap the `SSL_CTX` (+ SNI map) behind a `Mutex`; new `SSL_new` uses the new context, in-flight `SSL` keep theirs. **Simpler** than the Network restart-based rebind — no port retire/rebind, no accept gap. |

**Async byte bridge (the main engineering risk).** SSL is driven via **memory BIOs**, not `SSL_set_fd`:
`SSL_read`/`SSL_write` move plaintext to/from a pair of `BIO`s, and the backbone pumps ciphertext
between those BIOs and the socket using the existing async socket read/write. This fully decouples SSL
from the fd's blocking mode and composes with `async`/`await` and the kqueue/epoll readiness loop
(`SSL_ERROR_WANT_READ`/`WANT_WRITE` become "await more socket bytes / flush"). It is the same pattern
mature event-loop TLS stacks use; v1 may start with a blocking fd on a dispatch queue per connection
to land sooner, then move to memory-BIO + readiness for the 200k-rps budget.

**Concurrency / safety.** `SSL`/`SSL_CTX` are not Sendable; each `PortableTLSConnection` owns its `SSL`
and serializes access (one I/O actor or a `Mutex`), exactly as the POSIX connections wrap their fd.
The C shim is the sole `unsafe` surface and fails closed to `TransportError` on every non-success
return (the `NetworkFrameworkTLS` contract).

## Build plumbing

- `CHTTPBoringSSL` is a SwiftPM **C target** that `#include`s `<openssl/ssl.h>`; under
  `HTTP_PORTABLE_TLS=1` the manifest adds it + the OpenSSL header/lib search paths and `-lssl -lcrypto`
  (via `linkerSettings`; on macOS, Homebrew `openssl@3` prefix; on Linux, the distro `libssl-dev`).
  Off by default ⇒ the standard `swift build` graph is unchanged and apple-only.
- Unvendored-link flags make the package non-reusable *as a versioned dependency when the flag is on*;
  acceptable because this is a server and the flag is opt-in. The vendored-BoringSSL follow-up removes
  that caveat.
- `TransportBackbone` gains `case portableTLS`; `TransportConfiguration`/`TransportFactory` route to it
  only on explicit selection.

## Test strategy

- Mirror `NetworkFrameworkTLSTests` / `NetworkFrameworkMutualTLSTests` over real loopback through the
  portable backbone + `DevTLSIdentity`: one-way TLS + ALPN `h2`; `.required` rejects no-cert and
  honors the `verifyPeer` DER pin; **`.optional` accepts no-cert (subject `nil`) and surfaces a
  presented subject and refuses a pin-rejected cert** — the exact suite the Network backbone could not
  satisfy.
- **SNI multi-cert:** two identities, two server-names; assert each handshake selects the right leaf.
- **Interop** (the portability proof): handshake against `openssl s_client` and `curl` — not just
  Network.framework client ↔ server.
- Hot-reload-under-load parity with the G4b gate; ASan on the new transport; `swift format`/SwiftLint
  `--strict`; the gate runs under `HTTP_PORTABLE_TLS=1` and is **skipped** when the flag/lib is absent
  (so default CI stays apple-only), with the skip logged (no silent pass).

## Consequences

- **Unblocks** `.optional` client-auth and SNI multi-cert (both deferred since W2) on Darwin **and**
  lays the TLS half of Linux (G0); the `POSIXEpoll` accept loop is the remaining G0 I/O piece and
  plugs into the same `PortableTLSConnection`.
- **Dependency posture:** unchanged by default; an opt-in system-OpenSSL link when
  `HTTP_PORTABLE_TLS=1`, retired when the vendored-BoringSSL provider lands behind the seam.
- **Maintenance:** one C shim + one Swift adapter; the provider seam confines future churn (e.g.
  OpenSSL 3.x ABI drift, or the BoringSSL swap) to `OpenSSLProvider`/`CHTTPBoringSSL`.
- **Risk:** the memory-BIO async bridge is the novel part — prototype it behind the seam before wiring
  the abstraction; the blocking-fd fallback de-risks the first landing.

## Phased rollout

1. **Plumbing + handshake spike** — ✅ **shipped 2026-06-27.** `CHTTPBoringSSL` shim (macro wrappers,
   PKCS#12 → `SSL_CTX`, ALPN, memory-BIO handshake pump, legacy-provider load), `HTTP_PORTABLE_TLS`
   gating (default graph stays apple-only), and a gated test proving link + import + a TLS 1.3
   handshake negotiating ALPN `h2` over memory BIOs (kept as a regression test, not throwaway). *Gate
   met:* TLS 1.3 completes; ALPN negotiates `h2`; lint clean.
2. **`TLSProvider` + `OpenSSLProvider` + `PortableTLSConnection`** — identity from PKCS#12, memory-BIO
   byte bridge, `receive`/`send`/`close`. *Gate:* loopback echo (mirrors `assertLoopbackEcho`).
3. **`PortableTLSTransport`** — accept loop over `POSIXSocket`, `AsyncStream`, `boundPort`, `shutdown`.
   *Gate:* one-way TLS + ALPN suite green; interop with `curl`.
4. **mTLS tri-state** — `.none`/`.optional`/`.required` + `verifyPeer`/DER + `tlsPeerSubject`. *Gate:*
   the full mutual-TLS suite **including `.optional`** green.
5. **SNI multi-cert** + **hot reload** parity. *Gate:* SNI selection + reload-under-load gates green.
6. **Vendored BoringSSL provider** (separate effort) — swap `-lssl` for vendored sources behind the
   seam; remove the system-lib caveat. *Gate:* suites green with no system OpenSSL present.

## Alternatives considered

- **(a) Vendor BoringSSL up front.** The "pure" answer — self-contained, reproducible, matches the
  vendored-shim ethos (CCRC32-style). Rejected *as the first step* (not forever): the curation is XL
  and high-maintenance, and the seam lets it land later with no rework while the design is validated
  far sooner. It remains the recommended **endgame** (phase 6).
- **(c) swift-crypto BoringSSL + hand-rolled TLS records.** Rejected: swift-crypto ships no `libssl`,
  so this is "write a TLS 1.3 stack," an XXL security liability — exactly what a vendored stack exists
  to avoid.
- **SwiftNIO / swift-nio-ssl.** Excluded by CLAUDE.md ("no SwiftNIO reliance").
- **Stay Network.framework-only.** Leaves Linux unserved and `.optional`/SNI permanently blocked by
  the platform bug; defeats the portability goal.
</content>
