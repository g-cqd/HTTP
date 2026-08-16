# Bench — the comparative load battletest

End-to-end "vs the field" yardstick for the HTTP server. One runner (`run.sh`) drives our
`httpd-example` and every installed reference server with the **same** load generator (`oha`) across
a set of route scenarios on **byte-identical** routes, and reports the **median** of N rounds.

It complements the in-package microbenchmarks (`swift package --package-path Benchmarking/Benchmarks
benchmark`), which lock per-engine **instructions** and **mallocs/op**. This harness is the
wall-clock, many-servers comparison.

> **Iron Law.** Optimize only what you can measure; prove every change with a second measurement.
> Report **percentiles, not averages**, run in **release**, pin the workload, and run on a **quiet**
> machine. The harness now tells you when the machine was not quiet instead of leaving you to guess.

```sh
brew install oha jq                 # required: load generator + JSON parser (curl ships with macOS)
./Benchmarking/Bench/selftest.sh    # the harness's own tests — 33 assertions, no network needed
./Benchmarking/Bench/run.sh         # every installed server, both profiles, 3 rounds
```

- The decision this harness was rebuilt to serve, and the rule it must be judged by, is in
  [`DECISION.md`](DECISION.md) — written before the numbers.
- The measured result is in [`RESULTS.md`](RESULTS.md).
- The superseded pre-2026-08-01 rounds, and an audit of the claims made from them, are in
  [`history/`](history/README.md).

## The two-mode matrix

Every run measures our server in **two profiles**, and the difference between them is the point.

| profile | what it runs | what it is for |
|---|---|---|
| `floor` | the router alone — no middleware | the **only** column comparable to a peer, which runs a framework-floor handler |
| `full` | the chain `httpd-example` ships: metrics, decompression, compression, `Server`, `Date`, security headers, CORS, conditional GET (CRC32 ETag), Range | what you get when you deploy the example as written |

Selected with `HTTPD_PROFILE`; the default is `full` and only the exact string `floor` changes
anything, so a typo cannot downgrade a real deployment. `floor` is a benchmark posture, not a
recommendation — it serves no `Date` (RFC 9110 §6.6.1), no security headers and no conditional
requests.

**Only `ours` runs `full`.** `full` means *our* middleware chain; a peer has no such thing.
Re-implementing an equivalent in Rust, Go and JS would swap a measured confound for an unprovable
claim of equivalence — the exact failure this harness exists to end. Running each peer's *own*
middleware answers a different (and worthwhile) question: "is Hummingbird's gzip faster than ours?"
So the peers define the floor, we are compared to them at the floor, and our full column is priced
against our own floor.

## The four gates that make a number quotable

### 1. Byte equivalence, before any timing

Every route is fetched from every subject and the body digested. If two subjects that both implement
a route return different bytes, the run **aborts**. A benchmark comparing servers that answer
differently is not a benchmark.

Run against the field as it stood, this found five divergences that a status-code check could not
see — the per-server `GET /` greeting (30 B / 28 B / 71 B), Caddy's literal backslash-n, Caddy
answering `POST /echo` with 200 and an empty body, Django's re-serialised JSON, and the one nobody
guessed: `oha` sends `accept-encoding: gzip, compress, deflate, br` by default, so our full chain put
**58 bytes** of gzip on `/payload` where every peer put **1024**.

`ACCEPT_ENCODING` is therefore pinned to `identity`. To price content coding as its own question, set
it to a real negotiation list — and read the parity table, which will correctly refuse to compare the
compressing subject against the identity ones.

### 2. Rotated order, on a recorded host — graded on *external* load

The server order is a seeded shuffle, re-drawn each round; the seed and the order actually used are
recorded. The load average and thermal notes are sampled at the **start and the end** of every round.

The contention gate grades load the benchmark **did not cause**. Its first version graded the total
one-minute load average — which `oha` at 64 connections plus the server under test saturate by
design — so on a 10-core box every round graded `contended` even with nothing else running (measured
2026-08-02: single subject, load 1.54 → 10.63, back to 2.73 within 90 s of the run ending). Two
signals replace it:

- a **baseline** load average sampled before anything is built or started — at that moment the whole
  load is someone else's. A box already past `LOAD_CEILING_PER_CPU` here rejects **every** round, so
  the poisoned runs the gate was built for (load 16–30 from concurrent agent worktrees) stay
  rejected.
- per-round **external CPU**: the summed `ps` %cpu of every process outside the harness's own
  process tree (and excluding `kernel_task`, whose time tracks our own workload), normalised per
  CPU. Above the ceiling at either end of a round → `contended`; moving more than `LOAD_DRIFT_MAX`
  across the round → `drifted`.

The headline aggregate uses the clean rounds; when there are none, the whole run is stamped
**NOT-decision-grade** rather than reported as if it were. Beside the grade the runner prints the
widest per-cell `spread` across the eligible rounds as a **counter-signal**: rounds agreeing to a
percent are evidence of a stable run, but a tight spread never clears a contended or drifted grade —
a box under steady external load is stable *and* wrong.

### 3. One statistic: the median

The reported number is the **median of the eligible rounds**, stated in the run header and again
above every table. There is **no best-of anywhere**. The previous harness reported best-of-N,
justified as cancelling the thermal bias of a fixed server order; that justification is gone with the
fixed order, and best-of-N reports the luckiest round — not a thing any user experiences, and not
comparable against a median taken elsewhere.

`min`/`max` across rounds are carried beside every median and rendered as a `spread` column, flagged
above 1.5x. A median over three rounds that disagree by more than half is a number with no error bar.

### 4. A machine-readable record

`results/results.json` (`schema: http-bench/3`) carries the config, the pre-run baseline load, the
per-round host samples (total load *and* external CPU) and verdicts, the parity digests, every
individual sample and the aggregate — so two runs can be diffed without re-reading prose.

## The field

| server | role | install | port | profiles |
|---|---|---|---|---|
| **ours** (`httpd-example`) | the subject, one row per transport backbone | this repo | 8080 | `floor` + `full` |
| **rust** | `hyper` + `tokio` — the performance ceiling for the comparison | `brew install rust` | 8086 | `floor` |
| **go** | Go `net/http` stdlib | `brew install go` | 8084 | `floor` |
| **bun** | `Bun.serve` native server | `brew install oven-sh/bun/bun` | 8085 | `floor` |
| **hummingbird** | SwiftNIO framework — "are we competitive without NIO?" | `Bench/hummingbird/` (auto-built) | 8083 | `floor` |
| **vapor** | SwiftNIO framework | `Bench/vapor/` (auto-built) | 8088 | `floor` |
| **nginx** | C throughput/latency reference | `brew install nginx` | 8081 | `floor` |
| **caddy** | modern Go server | `brew install caddy` | 8082 | `floor` |
| **django-wsgi / django-asgi** | gunicorn / uvicorn, workers = cores | `Bench/django/` | 8087 | `floor` |

Django is **not** in the default `SERVERS` list: it is ~10x slower than the rest, so it dominates the
wall-clock cost of a run without changing any conclusion, and it has a dedicated harness in
`Benchmarking/Django/`. Add it explicitly when you want it.

The two SwiftNIO packages are nested in this repo, which SwiftPM mis-resolves ("product not found"),
so the harness copies each outside the repo tree to build it — carrying `.swift-version` with it,
without which `swiftly` selects no toolchain in the copy and both peers silently vanish from the
field.

## Scenarios

| scenario | exercises |
|---|---|
| `GET /plaintext` | framework floor — 13 identical bytes on every server |
| `GET /json` | serialize `{"message":"Hello, World!"}` |
| `GET /payload` | ~1 KiB body (32 × 32 B) |
| `GET /hello/world` | router + path/query parameter |
| `POST /echo` | request read + body round-trip |

**`GET /` is deliberately not measured.** Every server answers it with its own name, so it is not a
comparable route and never was — it was nonetheless the "framework floor" column in every published
round before this one. It remains as each server's identity page.

nginx and Caddy cannot echo a POST body without a scripting module. They now say so with a 405
(RFC 9110 §15.5.6), and the harness marks the cell N/A. Previously Caddy had no `/echo` matcher at
all and its catch-all returned 200 with nothing, which the ≥99 %-2xx check happily scored.

## Knobs

| var | default | meaning |
|---|---|---|
| `SERVERS` | the eight above | space-separated subset |
| `MODES` | `floor full` | which profiles to measure |
| `BACKBONES` | `posixKqueue swiftSystem` | our transport backbones, one subject each |
| `SCENARIOS` | the five above | `METHOD:PATH` tokens |
| `ROUNDS` | `3` | repeats of the whole field; the median is taken over the clean ones |
| `CONNECTIONS` | `64` | concurrent connections (closed loop) |
| `DURATION` / `WARMUP` | `5s` / `1s` | measured / throwaway per cell |
| `RATE` | _(unset)_ | per-connection rate → **open loop**, coordinated-omission-free latency |
| `ACCEPT_ENCODING` | `identity` | pinned content coding — the parity gate enforces the consequence |
| `SEED` | random | recorded; reuse it to reproduce an order |
| `LOAD_DRIFT_MAX` | `0.25` | absolute movement of the external busy-per-CPU fraction that marks a round `drifted` |
| `LOAD_CEILING_PER_CPU` | `0.5` | external busy-per-CPU (baseline load, or in-round external CPU) above which a round is `contended` |
| `PARITY_ENFORCE` | `1` | `0` records a mismatch and continues — diagnosis only, never for a number |
| `ECHO_BODY` | `{"x":1}` | request body for `POST /echo` |

```sh
MODES=floor SERVERS="ours rust go nginx" ./Benchmarking/Bench/run.sh    # apples-to-apples only
SERVERS=ours ROUNDS=5 ./Benchmarking/Bench/run.sh                       # price the chain, 5 rounds
SERVERS=ours MODES=full ACCEPT_ENCODING="gzip, deflate, br" ./Benchmarking/Bench/run.sh
RATE=2000 SERVERS="ours nginx rust" ./Benchmarking/Bench/run.sh         # open loop, real tail latency
```

## Methodology & caveats

- **Release only.** `httpd-example`, rust and the SwiftNIO peers are built `-c release`.
- **Loopback.** Runs hit `127.0.0.1`, so the NIC is out of the picture; this isolates
  framing/IO/allocation cost. A NIC-bound run is a separate exercise.
- **Closed loop by default** (`-c N`, max throughput). For tail-latency claims set `RATE` so
  queueing delay is not hidden by coordinated omission.
- **Quiet box.** Absolute RPS is contention-sensitive. The harness records and grades this rather
  than asking you to remember; a run stamped `NOT-decision-grade` is directional only.
- **Per-client cap.** Our default `maxConnectionsPerClient` (20) is a single-IP DoS guard that a
  loopback test trips, so `run.sh` launches us with `HTTPD_MAX_CONN=1000000` and `HTTPD_QUIET=1` (no
  access-log print, which no reference server performs either).
