# Working in `HTTP`

From-scratch, SwiftNIO-free HTTP/1.1, HTTP/2, HTTP/3, and WebSocket server library for Swift 6 (`g-cqd/HTTP`).

## Engineering principles

- **Verify claims with executable checks.** Write a failing test or measurement before changing behaviour; never state unmeasured performance or unverified behaviour as fact.
- **Strictness.** Swift 6 language mode, strict concurrency, strict memory safety where configured, and warnings as errors. No force-unwraps or force-casts in production paths.
- **Bounded work and safety.** Bound untrusted inputs, recursion depth, and memory before allocation; handle errors explicitly without crashing on hostile input.
- **Factual documentation.** Keep `README.md`, user docs, and `Package.swift` aligned with the current codebase—no roadmaps, speculative plans, or diary logs in public docs.

Keep protocol engines (`HTTPCore`, `HTTP1`, `HTTP2`, `HTTP3`, `HPACK`, `QPACK`, `WebSocket`) sans-I/O and free of transport imports. Network.framework / epoll live exclusively in `HTTPTransport`. Every parser/validator must cite the RFC section it implements and remain trap-free with bounded memory.

## Commands

```sh
swift test
scripts/ci-gates.sh
swift format lint --strict --recursive Sources Tests Package.swift
```

## Architecture records

Accepted architectural decisions live in `docs/adr/` (when present). Only add a new ADR for durable architectural choices; mark superseded records clearly.
