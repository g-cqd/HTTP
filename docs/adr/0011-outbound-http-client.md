# ADR 0011 — An outbound HTTP/1.1 client over the in-house transport and TLS 1.3 engine

- **Status:** Accepted
- **Context date:** 2026-11-27

## Context

The package served HTTP but could not make requests. Its consumers fetched upstream content through
`URLSession`, which on Linux means `FoundationNetworking` and therefore libcurl and the system OpenSSL — a
second HTTP stack, a second TLS stack, and the largest dynamic dependency of a server binary that otherwise
links none. apple-docs (whose crawler issues hundreds of thousands of conditional GETs to `developer.apple.com`,
`api.github.com`, `raw.githubusercontent.com`, and `swift.org`) was the motivating consumer (its ADR-0002 named
this gap).

Everything a client needs already existed on the server side: the POSIX readiness backbones (kqueue / epoll), the
sans-I/O RFC 8446 server engine with its record layer, key schedule, transcript, and swift-certificates chain
validation, the RFC 9112 field/framing validators, and the zstd / gzip / deflate decoders.

## Decision

1. **`TLSClientConnection`** (HTTPTLS): the sans-I/O TLS 1.3 client, the server engine's mirror — X25519 / P-256
   key shares, one HelloRetryRequest, AES-GCM / ChaCha20-Poly1305, SNI (RFC 6066), ALPN (RFC 7301), record size
   limit (RFC 8449), Appendix D.4 middlebox compatibility, KeyUpdate in both directions. The server certificate is
   validated by `TLSX509ChainValidator` (RFC 5280 path + RFC 6125 host) **before** its CertificateVerify is read;
   the CertificateVerify (ECDSA, Ed25519, and RSA-PSS through `TLSRSACertificateVerifier`) and Finished are
   verified before any application key installs. Trust anchors are `TLSTrustAnchors`, decoded once from DER roots
   or the platform PEM bundle and shared across connections. The record splitter, the non-handshake record
   verdict, the KeyUpdate driver, the Certificate codec, and CertificateVerify verification are shared with the
   server engine rather than duplicated.
2. **HTTP/1 client codec** (HTTP1): `RequestSerializer` (validated method / origin-form target / `Host` / field
   values — no CRLF injection outbound), `StatusLineParser`, and `ResponseParser` with RFC 9112 §6.3 response
   framing (`HEAD`, 1xx, 204, 304 bodyless; Content-Length; chunked; close-delimited; CL+TE refused).
3. **`TCPClientConnector`** (HTTPTransport): resolve off the cooperative pool, non-blocking connect completed on
   shared client readiness loops, then the same `TransportConnection` the server path uses.
4. **`HTTPClient`** (new product): per-origin keep-alive pool with a connection ceiling, request and connect
   deadlines, one retry of idempotent requests on a stale keep-alive connection, policy-filtered redirects
   (HTTPS → HTTP refused by default; credentials dropped cross-origin), and `zstd` / `gzip` / `deflate` content
   decoding under a decompressed-size bound.

HTTP/2 and HTTP/3 client support, proxies, cookies, and connection coalescing are out of scope.

## Consequences

- A consumer can drop `URLSession` / `FoundationNetworking` entirely; on Linux nothing links libcurl or OpenSSL.
- The TLS client is verified back-to-back against the in-house server (1-RTT, HelloRetryRequest, RSA-PSS,
  hostname mismatch and untrusted-root rejection) and, opt-in (`HTTP_CLIENT_LIVE=1`), against
  `developer.apple.com` (RSA) and GitHub (ECDSA).
- The shared helpers changed server code paths (record splitting, KeyUpdate, client-certificate verification)
  without changing their behavior; the full HTTPTLS suite covers both roles.
