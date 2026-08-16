# Bench — comparative results, and the verdict against the pre-registered rule

Read [`DECISION.md`](DECISION.md) first. It fixes the rules these numbers are tested against, and it
was committed before the numbers existed (`952bc1d`, one commit ahead of this file's data). The
superseded pre-2026-08-01 rounds, and an audit of the claims made from them, are in
[`history/`](history/README.md).

## 2026-08-16 — every middleware-cost MAGNITUDE below is superseded

The paired estimator that produced them was defective, and it produced two contradictory answers
that between them make neither quotable:

- **"6–16 %, full slower 42/55"** (Rule 1 below) came from a host at load 15–37 on 10 cores, where
  the per-round ratios ran 0.42–1.58. The contention gate of the time could not separate that box
  from a quiet one, because it graded the *total* load — which the benchmark itself saturates.
- **"−0.4 % to −1.9 %"** (2026-08-02 runs, never written up here) reported the chain as *faster*
  than the floor it strictly contains — a physically impossible sign. Forensics on the retained
  data: in the full-field run the two profiles sat 4–8 shuffled slots apart and the estimator
  paired them anyway; in the isolation run every cell — floor and full, 13 B and 1 KiB — pinned at
  a ~66.4k RPS client-side ceiling, so the run measured the load generator's ceiling, not the
  server, and full/floor > 1 in 24 of 25 reconstructed cells regardless of order.

What still stands is the **direction**: `full` slower than `floor` in 42 of 55 paired rounds, and in
28 of 35 even when full held the favored order slot. What does not stand is any magnitude: **no
recorded run can price the chain honestly.** The estimator now schedules pairs back-to-back, refuses
pairs beyond an order-gap bound, and verdicts an impossible sign as `sign-artifact` instead of
printing it (see [`README.md`](README.md)); a run on a quiet host at a non-saturated operating point
(vary `CONNECTIONS`, or set `RATE`) is required before any cost figure is quoted again.

## Verdict, in one paragraph

**The harness is fixed; the host is not, and it is the host that decides.** The byte-equivalence gate
found five ways the field had been answering differently — one of which had our server gzipping
`/payload` to 58 bytes while every peer sent 1024 — and the field now demonstrably serves identical
bytes. With that fixed, the two-mode matrix says our middleware chain costs **6–16 % of throughput**
(superseded 2026-08-16 — see the banner: direction only, no magnitude is quotable)
and is slower in **42 of 55 paired rounds**, so the direction is established; the magnitude is not,
because every round on this machine was contended and the pre-registered invalidation clause fires.
**Rule 1 does not fire. Rule 2 may not fire at all.** No default changes on this evidence, which is
the outcome `DECISION.md` predicted and the correct one.

## Grade: NOT decision-grade

Both runs below stamped themselves `NOT-decision-grade` and the stamp is binding under Rule 3.

| run | rounds | host load, 10 logical cores | every round |
|---|---|---|---|
| full field, 11 subjects | 3 | 16.03 → 30.23 → 27.03 → 19.96 | `drifted+contended` / `contended` |
| paired A/B, `ours` only | 11 | 15.56 → … → 30.93, peak 37.65 | `contended`, 2 also `drifted` |

This machine ran three concurrent coding agents for the entire session. Rule 3 clause 2 (no clean
round) fires on both runs, and clause 3 (spread > 1.5x on the quoted cell) fires on most cells. **The
deliverable of PERF-2 is a harness that would produce decision-grade numbers on a quiet host, plus
the honest statement that this host cannot.**

## What the byte-equivalence gate caught

This is the part that does not depend on a quiet machine, and it is the most consequential finding.
Five divergences, every one invisible to the status-code check the harness used before:

| # | what | measured |
|---|---|---|
| 1 | **`oha` sends `accept-encoding: gzip, compress, deflate, br` by default.** Our full chain honoured it; no peer compresses. | `/payload`: ours **58 B** gzipped vs Go and our own floor **1024 B** |
| 2 | **`GET /` — the "framework floor" scenario — returned a different body from every server.** | hyper 30 B, Go 28 B, ours 71 B |
| 3 | **Caddy answered `POST /echo` with 200 and an empty body.** No `/echo` matcher existed; the catch-all replied. The ≥99 %-2xx rule scored it. | `RESULTS.md` at `6133458` ranks caddy **4th on POST /echo at 92,584 rps** for returning nothing |
| 4 | **Caddy put a literal backslash-n on `/hello/<name>`.** Caddyfile quoted strings do not interpret escapes. | 15 B vs the field's 14 B ending in `0x0A` |
| 5 | **Django diverged on three routes and lacked `/health`.** `JsonResponse`'s `", "`/`": "` separators; a missing trailing newline; `/echo` re-serialising instead of echoing. | `/json` 2 B longer than the field's compact object |

Finding 1 is the one nobody could have guessed and the one that most damages the prior rounds: every
published `/payload` cell compared a server compressing a 1 KiB body against servers that were not —
a different wire payload *and* a per-request compression cost no peer paid. `ACCEPT_ENCODING` is now
pinned to `identity`, and the gate proves the consequence rather than asserting it.

After the fixes, all five scenarios PASS across all eleven subjects.

## Rule 1 — what the middleware costs

> **Superseded 2026-08-16** (see the banner above): the magnitudes in this section are products of
> the defective estimator and must not be quoted. The 42/55 sign count stands.

Paired within each round, `ours(posixKqueue)`, 11 rounds, 3 s each, `identity` coding.
`cost` = 1 − median(full ÷ floor); `full slower` is the sign count.

| scenario | cost | ratio range | full slower |
|---|---:|---:|---:|
| `GET /plaintext` | **14.0 %** | 0.42–1.24 | 9/11 |
| `GET /json` | **14.2 %** | 0.48–1.23 | 10/11 |
| `GET /payload` | **16.0 %** | 0.68–1.48 | 9/11 |
| `GET /hello/world` | **12.1 %** | 0.52–1.30 | 7/11 |
| `POST /echo` | **6.1 %** | 0.57–1.58 | 7/11 |

**Pooled: 42 of 55 paired rounds had `full` slower than `floor`.** Under a null of no difference that
is a coin flip per round, so 42/55 is `p ≈ 8 × 10⁻⁵`. The chain genuinely costs something, and that
conclusion needs no magnitude and survives the contended host.

**Rule 1 does not fire.** Its branches are `>25 %`, `<10 %`, and `10–25 %`, and the point estimate of
6–16 % straddles the boundary between the lower two. The per-round ratios run from 0.42 to 1.58 —
ratios above 1.0 are physically impossible, so the dispersion is host noise, not effect. This host
cannot distinguish "the chain costs 8 %" from "the chain costs 20 %", and those imply different
decisions. **No middleware work is authorised on this evidence.**

What it *does* settle: the chain does not cost 30 % or 50 %. So the claim that our middleware
explains a 13–22 % gap to hyper is **not supportable** — the chain is the right order of magnitude to
be a *contributor*, not an explanation. I predicted 5–12 % in `DECISION.md`; the measurement came in
slightly above that, at 6–16 %. The prediction was low.

### The estimator matters more than the data here

The three-round full-field run, analysed by the obvious method — median of `full` over median of
`floor` — produces this:

| subject | scenario | "cost" by ratio of medians |
|---|---|---:|
| `ours(posixKqueue)` | `/plaintext` | **−23.1 %** |
| `ours(posixKqueue)` | `/json` | **−13.1 %** |
| `ours(posixKqueue)` | `/hello/world` | **−18.8 %** |

A negative cost means the full middleware chain made the server *faster*, which cannot happen: `full`
runs `floor`'s code and then nine more middlewares. Two independently-drifting medians do not share a
denominator. The paired estimator on the same kind of data returns a physically possible answer,
which is why `report_paired` exists and why the ratio of medians is not reported anywhere.

## Rule 2 — the gap to hyper, at the floor

**Rule 2 may not fire.** Rule 3 clauses 2 and 3 both apply to the only run that measured hyper. The
table is recorded for completeness and must not be quoted as a comparison.

Full field, 3 rounds, median, `identity` coding, best local backbone per route. **Every cell is
host-contended; `spread` is max/min across the three rounds.**

| scenario | rust (hyper) | spread | ours, best floor | spread | G |
|---|---:|---:|---:|---:|---:|
| `GET /plaintext` | 59,289 | 1.04 | 41,470 `kqueue` | 1.08 | 0.70 |
| `GET /json` | 53,506 | 1.14 | 45,495 `kqueue` | 1.57 ⚠ | 0.85 |
| `GET /payload` | 58,988 | 1.35 | 47,084 `kqueue` | 2.28 ⚠ | 0.80 |
| `GET /hello/world` | 55,964 | 1.29 | 34,868 `kqueue` | 1.40 | 0.62 |
| `POST /echo` | 50,815 | 1.16 | 37,606 `swiftSystem` | 1.75 ⚠ | 0.74 |

Taken at face value this is Rule 2's "gap is real" branch (`G < 0.85` on four of five). **It may not
be taken at face value**, for a reason visible in the table itself: our cells carry spreads up to
2.28 while hyper's stay between 1.04 and 1.35. Our subjects were, by the luck of the rotation,
sampled during the worst of the contention. The same run has `ours(posixKqueue):full` beating
`ours(posixKqueue):floor` on four of five scenarios — an impossibility that disqualifies these cells
in both directions. A rerun on a quiet host is the only way to fire Rule 2, and it is cheap:
`MODES=floor SERVERS="ours rust" ROUNDS=5 ./run.sh`.

The one observation that is probably robust, because it is large and consistent across both runs and
across all four prior rounds in `history/`: **hyper's tail is much tighter than ours.** Its p99 sits
at 3.5–14.6 ms where ours sits at 11–39 ms, on a host that was punishing both. Tail latency, not
throughput, remains the honest next target — which is what the June `RESULTS.md` and both July
reviews also concluded, by different routes and from worse data.

## What was wrong in the prior reviews' benchmark claims

Recomputed from the raw rows now preserved in [`history/`](history/README.md). Most of the arithmetic
holds up; the framing does not. Full detail there, in summary:

- **"Ahead of nginx and Bun" is false on `/payload`** — nginx led our best local backbone by 3.5 %.
- **Round 1's throughput headline and its tail headline are different measurements.** Throughput took
  the better of two backbones per route; the p99 was `posixKqueue` only. The much-quoted **37.8 ms**
  routed p99 belongs to the kqueue cell whose 30,838 RPS was *discarded* in favour of swiftSystem's
  45,664. On the backbone that produced the winning number the median p99 is **12.05 ms**.
- **"Level with Go"** describes a 1–4 record (−3.1 % to −15.4 % on the four losses).
- **"Level with the SwiftNIO frameworks" understates us** — 5/5 against Hummingbird, 4/5 against Vapor.
- **The June `RESULTS.md` this file replaces contradicted all four July rounds** and was the most
  misleading artifact in the repository: absolutes ~3x higher, and a claim of *"~1.7–1.9x
  Hummingbird's and Vapor's throughput across every scenario"* where the July rounds put us at
  **1.00–1.11x**. It was best-of-1 on a quiet box against medians-of-3 on a loaded one, and carried
  no pointer to the later numbers.
- **Both SwiftNIO peers had silently dropped out of the field** in the runs taken from this
  worktree: the out-of-tree build copy carried no `.swift-version`, `swiftly` selected no toolchain,
  and the harness printed `skip hummingbird (build failed)` among its build noise. A comparison
  against "the SwiftNIO frameworks" can be reported with neither of them present.

## Reproduce

```sh
./Benchmarking/Bench/selftest.sh                                       # 48 assertions, no network
./Benchmarking/Bench/run.sh                                            # full field, both profiles
SERVERS=ours BACKBONES=posixKqueue ROUNDS=11 DURATION=3s ./Benchmarking/Bench/run.sh   # the A/B above
MODES=floor SERVERS="ours rust" ROUNDS=5 ./Benchmarking/Bench/run.sh   # what Rule 2 needs, quiet box
```

Machine-readable output lands in `results/results.json` (`schema: http-bench/2`) with the per-round
host samples, the parity digests, every sample and both aggregates.
