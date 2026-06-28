# Investigation — ADJSON vs Foundation for the JSON work

**Question.** Does swapping the `/json` + `/echo` JSON work on *our* side from Foundation's
`JSONSerialization` to the local sibling library **ADJSON** (its Foundation-free `ADJSONCore`: a
single-pass tape parser + cursor re-encoder) make the Swift server faster?

**Answer.** At the tiny payloads of the main matrix it's a **wash** (JSON isn't the bottleneck there).
At **realistic payload sizes (tens of KB) ADJSON is ~1.7× faster** on `/echo` (parse + re-serialize),
with ~40% lower per-request latency — and it's *more correct*: it preserves object key order, which
Foundation does not. Recommendation: **adopt it for the JSON-heavy paths**, behind the bench layer (not
the core library — see Caveat).

Wired in behind a runtime toggle so the harness can A/B back-to-back:
`BENCH_JSON=foundation|adjson` (run.sh: `OURS_JSON=…`). Host: Apple M3, Swift 6.4 release, oha 1.14,
loopback, every cell `ok=100%`.

## Result 1 — tiny payloads (the main-matrix routes)

`/json` encodes `{"message":"Hello, World!"}`; `/echo` parses + re-emits a ~90-byte object. ours-only,
back-to-back (controls for thermal drift).

| scenario | metric | Foundation | ADJSON | Δ |
|---|---|---:|---:|:--:|
| json | ceiling rps (`-c64`) | 145,849 | 145,661 | ~0% |
| json | per-request p50 (`-c1`) | 0.041 ms | 0.040 ms | ~0% |
| echo | ceiling rps (`-c64`) | 131,369 | 133,648 | **+1.7%** |
| echo | per-request p50 (`-c1`) | 0.044 ms | 0.042 ms | **+5%** |

At this size the JSON encode/parse is a negligible slice of per-request cost (HTTP framing + the
request lifecycle dominate), so the two are statistically indistinguishable. Swapping JSON libraries
can't speed up work that isn't the bottleneck.

## Result 2 — a realistic 42 KB body (where JSON *is* the work)

`POST /echo` of a 42,646-byte JSON document (200 mixed-type objects: ints, floats, bools, nulls,
arrays, nested objects) — i.e. a full parse + re-serialize per request.

| backend | calibration | rps | p50 | vs Foundation |
|---|---|---:|---:|:--:|
| Foundation | per-request (`-c1`) | 1,268 | 0.785 ms | — |
| **ADJSON** | per-request (`-c1`) | **2,090** | **0.472 ms** | **1.65× rps · −40% latency** |
| Foundation | ceiling (`-c64`) | 5,629 | 11.29 ms | — |
| **ADJSON** | ceiling (`-c64`) | **9,689** | **6.42 ms** | **1.72× rps · −43% latency** |

ADJSON's tape parser (no intermediate `NSDictionary`/`NSArray` object graph; re-encode walks the tape
straight to UTF-8 bytes) is where the ~1.7× comes from. The bigger the JSON, the wider the gap.

## Correctness — ADJSON is also more faithful

Both backends round-trip the 42 KB body to a **semantically-equal** document. But on key ordering they
differ, visible on any object:

```
sent:        {"message":"Hello, World!","numbers":[1,2,3,4,5],"flag":true,"nested":{…}}
Foundation:  {"flag":true,"message":"Hello, World!","nested":{…},"numbers":[…]}   ← keys re-sorted
ADJSON:      {"message":"Hello, World!","numbers":[1,2,3,4,5],"flag":true,"nested":{…}}  ← order preserved
```

`JSONSerialization` round-trips through an unordered dictionary and **re-sorts keys**; ADJSON's
`OrderedDictionary`-backed values **preserve insertion order** — matching the input *and* Django's
`json` module. For an echo/proxy/pass-through endpoint, order preservation is the correct behavior.

## How it's wired ("locally only")

- `ours/Package.swift` adds `.package(path: "../../../../ADJSON")` and depends on the **Foundation-free
  `ADJSONCore`** product only (tape parse + `JSONValue` + cursor `encodedBytes`). The umbrella's
  Codable/Schema/macros are not pulled into the build.
- ADJSON resolves its own **ADFoundation** sibling from a local checkout via `ADFOUNDATION_PATH`
  (run.sh sets it to `…/g-cqd/ADFoundation` automatically) — **no git fetch of the AD-family**.
- The hot paths (`ours/Sources/ours-bench/main.swift`):
  ```swift
  // /json — build + encode, no Foundation:
  let value: JSONValue = .object(["message": .string("Hello, World!")])
  return .json(try value.encodedBytes())
  // /echo — tape parse, then re-encode straight from the cursor (no value tree built):
  let document = try ADJSON.parse(body)
  return .json(try document.root.encodedBytes())
  ```

```sh
# reproduce the A/B (ours-only, back-to-back):
SERVERS=ours SCENARIOS="json echo" OURS_JSON=foundation ./run.sh
SERVERS=ours SCENARIOS="json echo" OURS_JSON=adjson      ./run.sh
```

## Caveat — keep it out of the core library

The main `HTTP` package is deliberately **SwiftNIO-free, Apple-only, near-zero-dependency** (its
first-party `HTTPRequest`/`HTTPResponse`/`HTTPFields` exist precisely to avoid pulling in anything).
ADJSON brings `ADFoundation`/`ADFCore` + `OrderedCollections` (and resolves, though doesn't compile,
swift-syntax). That's fine for an *application/bench* target that opts in, but it would violate the
core library's dependency policy. So the right home for an ADJSON dependency is the **consumer layer**
(an app, or this bench) — not `HTTPCore`/`HTTPServer`. The library should keep returning `[UInt8]` and
let the application choose its JSON engine. This investigation lives entirely in the bench package and
leaves the core untouched.

## Verdict

| | tiny payloads | ~42 KB payloads | correctness |
|---|---|---|---|
| **ADJSON vs Foundation** | tie (within noise) | **~1.7× faster, −40% latency** | **key order preserved** (Foundation re-sorts) |

Worth adopting wherever JSON bodies are non-trivial; immaterial where they're a few bytes. Either way,
keep the dependency in the application/bench layer, not the core HTTP library.
