# ADR 0001 — Bespoke HTTP currency types (not apple/swift-http-types)

- **Status:** Accepted
- **Context date:** 2026-06

## Context

`HTTPCore` defines first-party currency types — `HTTPRequest`, `HTTPResponse`, `HTTPField`,
`HTTPFieldName`, `HTTPFields`, `HTTPMethod`, `HTTPStatus` — that closely mirror
[`apple/swift-http-types`](https://github.com/apple/swift-http-types). That package is under the
`apple/*` org, so it is *allowed* by CLAUDE.md's dependency policy, and it is battle-tested
(URLSession, Vapor, swift-nio's NIOHTTPTypes). The question: adopt it, or keep our own?

## Decision

**Keep the bespoke types.** Do not depend on `apple/swift-http-types`.

## Rationale

1. **Zero-copy parser integration.** The engines parse over a borrowed `RawSpan` via `ByteReader`
   and materialize owned values exactly once. Our types are built to be constructed from validated
   byte ranges (`HTTPFieldName(validating:)`, unchecked fast paths for trusted parsers). swift-http-types'
   API is `String`/`Substring`-centric and would reintroduce intermediate allocations at the boundary.
2. **Version-agnostic, body-less messages.** Our `HTTPRequest`/`HTTPResponse` carry no body (parsers
   return body bytes separately, enabling streaming) and one shape serializes to h1/h2/h3. This is a
   deliberate fit for the sans-I/O design.
3. **Stated principle.** The README lists "own currency types, zero external dependencies" as a design
   pillar; the only runtime dependency is `apple/swift-system` (transport only).
4. **Control over validation & limits.** Field validation is tied to `HTTPLimits` and the exact RFC
   9110 grammar we enforce for smuggling/injection defense.

## Tradeoffs / costs

- ~500 LOC of currency types we own and test (vs reusing a maintained package).
- No automatic interop with the wider swift-http-types ecosystem.

## Mitigations

- If interop is ever needed, add a thin, *optional* conversion shim module
  (`HTTPCore <-> HTTPTypes`) rather than adopting the dependency wholesale.
- Revisit if swift-http-types gains a `Span`/`RawSpan`-based zero-copy construction API.
