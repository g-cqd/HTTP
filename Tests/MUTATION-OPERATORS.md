# Mutation-resistance checklist

We do not run an automated mutation-testing tool (evaluated `muter` and `SwiftMutationTesting`;
declined — keeps the toolchain pure-Swift / dependency-free). Instead we write **mutation-resisting
tests by construction**: for every security- or correctness-critical branch, a test must fail under at
least one of the operators below applied to that branch. This file is the checklist a reviewer applies
when reading a test, and the menu of mutations to spot-check with during development (temporarily edit
the engine, confirm a test goes red, revert).

## Operators

| # | Operator | Example mutation | What kills it |
|---|----------|------------------|---------------|
| M1 | **Relational boundary** | `<` ↔ `<=`, `>` ↔ `>=` | A test at the *exact* boundary value (e.g. `n == cap`, not just `n > cap`). |
| M2 | **Equality flip** | `==` ↔ `!=` | Assert the true branch *and* a near-miss false branch. |
| M3 | **Logical operator** | `&&` ↔ `\|\|` | A case where exactly one operand is false. |
| M4 | **Off-by-one constant** | `cap` → `cap ± 1`, range `a...b` → `a...b±1` | Tests at both `cap` (passes) and `cap+1` (trips). |
| M5 | **Constant replacement** | `1000` → `0`, `0x7F` → `0xFF` | Exact-equality on the produced/required value, not a range/`!= nil`. |
| M6 | **Throw / guard deletion** | remove a `throw` or `guard` | A negative test asserting the *specific typed error* (use `Oracles.expectThrows`). |
| M7 | **Negation removal** | `guard !x` → `guard x`, drop a `!` | Both the satisfied and the violated input are asserted. |
| M8 | **Branch / arm swap** | swap two `switch` arms or `if/else` bodies | Each arm asserted against a distinct expected output (no shared expectation). |
| M9 | **Assignment / increment** | `+=` → `-=`, `x = a` → `x = b` | Assert the exact resulting state after the operation, not just "no throw". |

## Anti-patterns these replace

- `#expect(x != nil)` — survives M5/M6. Assert the *value*, or the *specific error*.
- `#expect(throws: (any Error).self)` — survives M6. Assert the concrete typed error (`expectThrows` checks the payload).
- "all-true" / "all-present" fixtures — survive M5/M7 ("always emit X" mutations). Test each attribute in isolation.
- a single in-range sample — survives M1/M4. Test the boundary pair (`b` valid, `b+1` invalid).
- `n > cap` only — survives M1/M4. Test `n == cap` (allowed) and `n == cap+1` (rejected).

## Coverage map (the branches hardened against these operators)

| Branch (source) | Operators | Test |
|-----------------|-----------|------|
| `WebSocketCloseCode.isValidOnWire` ranges | M1 M4 M8 | `Tests/WebSocketTests/WebSocketCloseCodeTests.swift` |
| `HTTP2FlowControlWindow.{increase,shiftInitial,reserve}` | M1 M4 M7 M9 | `Tests/HTTP2Tests/HTTP2FlowControlWindowTests.swift` |
| `HTTP2Connection.chargeStreamReset` cap + decay window | M1 M4 | `Tests/HTTP2Tests/HTTP2AbuseBudgetTests.swift` |
| `SetCookie.headerValue` per-attribute emission | M5 M7 | `Tests/HTTPCoreTests/CookieTests.swift` |

Reviewed and **already** satisfying the checklist (no change needed):
- `HTTPStatus.kind` — boundary-parameterized over every class edge (199/200, 299/300, …).
- HTTP/1 smuggling precedence (`RequestParserTests`) — each CL/TE combination asserts its concrete typed error (M6).
- `HPACKInteger.decode` / `QPACKInteger.decode` magnitude bound — `roundTrips(maxValue)` decodes a value whose
  final accumulation hits `added <= maxValue - value` at exact equality, so the `<=`→`<` mutation (M1) is
  already killed; the padding-attack test covers the shift guard (M6).
