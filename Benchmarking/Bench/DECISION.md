# PERF-2 — the decision rule, recorded before the numbers

This file is committed **before** the two-mode matrix has produced a result, for the same reason
`Benchmarking/Benchmarks/Benchmarks/HTTPBenchmarks/RoutingBenchmarks.swift` records its rule before
its measurements: a threshold chosen after seeing the data is not a threshold, it is a caption. Three
separate reviews have now produced comparative numbers for this server and none could conclude
anything from them. The failure mode this time would be to produce a fourth set and narrate it.

Git history is the proof of ordering. If the rules below were edited after the results landed, that
edit is a commit and it is visible.

## The question

Two rounds of comparative benchmarking reported this server at 13–22 % behind Rust/hyper, then at
8–19 % lower again at a later commit. Both reviews said in their own text that the numbers could not
support a conclusion. The specific decision waiting on them is:

> Is there a real request-path gap to close, and is our middleware chain a first-class optimization
> target — or was the reported gap an artifact of measuring our full production stack against
> framework-floor handlers?

## What is being measured

A two-mode matrix. `floor` = our router alone, which is the same work a peer's floor handler does.
`full` = the chain `httpd-example` ships. Every peer runs its floor. Bodies are byte-identical across
the field and proved so before timing; content coding is pinned to `identity`; server order is
shuffled per round; the host load is recorded at the start and end of every round; the statistic is
the median of the clean rounds.

Only `ours` runs `full`, and that is deliberate. `full` means *our* middleware chain. Re-implementing
an equivalent in Rust, Go and JS would replace a measured confound with an unprovable claim of
equivalence — the exact failure this work exists to end. Running each peer's *own* middleware would
answer a different and also worthwhile question ("is Hummingbird's gzip faster than ours?"), which is
not this one. So the peers define the floor, we are compared to them at the floor, and our full
column is priced against our own floor.

## Rule 1 — what the floor-vs-full difference decides

Let `D` be the median throughput drop from `ours(floor)` to `ours(full)` on the same backbone and
route, on clean rounds.

- **`D` > 25 %** — the chain is a first-class optimization target. Promote the audit's middleware
  items (metrics-handle churn, the CRC32 ETag over the whole body, per-request header allocation) to
  P1, and every future peer comparison must be quoted from the `floor` column with the chain's price
  stated beside it.
- **`D` < 10 %** — the chain does **not** explain the reported gap to hyper. Any claim that "our
  middleware accounts for the difference" is refuted and must stop being made, including by me in the
  write-up of this very run.
- **10 % ≤ `D` ≤ 25 %** — a partial explanation. The gap must never again be quoted without saying
  which profile produced it, and the chain is a P2 target behind whatever Rule 2 finds.

## Rule 2 — what the floor-vs-hyper difference decides

Let `G` be the median throughput of `ours(floor)`, best local backbone, as a fraction of `rust`'s on
the same route and rounds.

- **`G` ≥ 0.90 on four of five routes** — the "13–22 % behind Rust" finding was substantially a
  middleware artifact. PERF-2 closes with no server-side work, and the finding is recorded as
  answered rather than deferred.
- **`G` < 0.85 on three or more routes** — the gap is real, lives in the request path, and survives
  the removal of every confound. It becomes the next measure-first target, and the specific
  sub-target is whichever of throughput or tail (p99) is further from hyper proportionally.
- **In between** — no server work is authorised on this evidence; the honest output is a repeat run
  on a quiet host.

## Rule 3 — what invalidates the whole thing

Any of these means the run answers nothing and neither Rule 1 nor Rule 2 may fire:

1. The parity gate fails. Different bytes, no comparison.
2. No round is marked `clean` — i.e. every round drifted past `LOAD_DRIFT_MAX` or ran above
   `LOAD_CEILING_PER_CPU`. The harness stamps the run `NOT-decision-grade` and that stamp is binding.
3. The cell being quoted has a max/min spread across rounds above 1.5x. A median over three rounds
   that disagree by more than half is a number with no error bar, and the July round-1 routed cell
   (23,848 → 50,383 → 30,838 RPS) is the standing example of why.

## What I expect, stated now so it can be wrong

From a two-subject smoke run taken while building the harness — `ours(swiftSystem)` floor 51,816 vs
full 48,579 RPS on `/plaintext`, and 49,715 vs 47,095 on `/payload`, three rounds, contended host — I
expect **`D` in the 5–12 % range**: mostly Rule 1's "does not explain it" branch, possibly its lower
"partial" branch. I therefore expect to have to write that our middleware does **not** account for a
13–22 % gap, which is the opposite of the tidy explanation this work was set up to find.

For Rule 2 I expect `G` between 0.85 and 0.95 — the "in between" branch, i.e. no authorisation to
change anything. I expect the tail, not the throughput, to be where hyper is furthest ahead.

I expect Rule 3 clause 2 to fire on this host. It has run concurrent agents all session; the load
average has been 8–20 on 10 cores throughout. **The numbers this run produces are directional
evidence about the harness, not decision-grade evidence about the server**, and the correct output of
PERF-2 is a harness that *would* produce decision-grade numbers on a quiet host, plus the honest
statement that this host cannot.

## What would change my mind

- `D` above 25 % would make the middleware the story, and I would want it confirmed by a per-
  middleware ablation (drop one at a time) before anyone optimised anything.
- `G` below 0.85 at the floor with a clean host would make the request path the story.
- A parity failure appearing *after* this commit would mean a server changed its bytes under us, and
  the first thing to check would be the harness, not the server.
- Two consecutive clean-host runs disagreeing by more than the spread flag would mean the whole
  loopback methodology is unsound at this resolution and the comparison should move to a fixed-rate
  open-loop measurement (`RATE=`) or off the box entirely.

## Addendum, 2026-08-16 — Rule 1 has not fired, and its earlier inputs are void

Recorded after the fact, as this file's own rule requires it to be visible. Two harness defects
were found and fixed (see the commits touching `lib/host.sh` and `lib/report.sh`, and the
supersession banner in [`RESULTS.md`](RESULTS.md)):

1. the contention gate graded the *total* load average, which the benchmark itself saturates, so
   `clean` was unreachable and NOT-decision-grade stopped meaning anything;
2. the paired estimator ignored where in the shuffled order its two cells ran, and would print a
   physically impossible negative cost rather than admit a run could not resolve the effect.

Consequently the **6–16 %** figure quoted against Rule 1, and the **−0.4 % to −1.9 %** from the
2026-08-02 reruns, are both void as inputs to Rule 1 — in opposite directions, which is exactly why
neither may be kept. The 42/55 sign count stands as direction. `D` remains unmeasured; Rule 1 waits
for a clean-host run of the fixed harness at an operating point that is not client-saturated. No
rule text above this line changed.
