# history — the raw rows behind the pre-PERF-2 comparative rounds

Four complete runs of the old comparative harness were taken on 2026-07-31 and 2026-08-01. Their
numbers were quoted in review prose and in a planning document; **none of them was ever written into
a tracked file**, and every one of them lived only in a `/tmp` scratch directory that the next reboot
would have taken. They are preserved here because the claims made from them are still in circulation
and a reader deserves to check them.

**Every number in this directory is superseded.** These runs predate the byte-equivalence gate, the
floor/full profile split, the pinned content coding, the rotated server order and the recorded host
state. Do not quote them as a measurement of anything. They are kept as the provenance of claims, and
as the regression fixture that the new harness's assertions are built from.

## The files

| file | commit | date | what it is |
|---|---|---|---|
| `6a0bbc0_results.tsv` | `6a0bbc0` | 2026-07-31 16:49 | "Review 4", the comparative review |
| `63031f5-rerun_results.tsv` | `63031f5` | 2026-07-31 18:08 | the baseline round 2 was measured against; never published as a table |
| `ea6bac3_results.tsv` | `ea6bac3` | 2026-07-31 23:45 | "Review 5", the re-audit |
| `b0f9073_results.tsv` | `b0f9073` | 2026-08-01 15:43 | a fourth run nobody wrote up |

Columns: `scenario-key`, `server`, `rps`, `p50`, `p99`, `p99.9`. Each file holds three repeat rounds
of eight servers across five routes (120 rows). The reviews computed medians from these by hand.

## What was wrong with all four

Common to every run, and the reason PERF-2 exists:

- our server ran its **full production middleware chain** against peers running framework-floor
  handlers, so the headline comparison is between two different programs;
- `oha`'s default `accept-encoding: gzip, compress, deflate, br` meant our chain **gzipped** bodies
  the peers returned as identity — on `/payload`, 58 bytes against 1024;
- `GET /` ("framework floor") returned a **different body from every server** — 30 B, 28 B, 71 B;
- Caddy answered `POST /echo` with **200 and an empty body**, and `/hello/<name>` with a literal
  backslash-n;
- the server order was **fixed**, on a host whose load moved 5.31 → 16.77 between two of the runs;
- `/payload` built a fresh 1 KiB `String` per request on our side only.

## Claims made from these files, checked against the rows

Verified correct, arithmetically, against the raw rows:

- Round 1's "13–22 % behind Rust" (the per-route range is 12.8–22.2 %).
- Round 1's p99 line, and round 2's "71–83 % of Rust" and "p99 12.2–18.4 vs 3.8–9.0".
- Round 2's "8–19 % lower across the local backbones" **against `63031f5`** (the range is 8.3–18.7 %).
- The routed cell swinging 23,848 → 50,383 → 30,838 RPS — though note that is a swing across the
  three repeat rounds **inside** the `6a0bbc0` run, not between two published rounds.

Not supported by the rows:

- **"Ahead of nginx and Bun" (round 2) is false on `/payload`**: nginx 40,740 against our best 39,351,
  i.e. nginx 3.5 % ahead. Bun is genuinely behind on all five.
- **Round 1's throughput headline and its tail headline are different measurements.** The throughput
  figure takes the better of the two backbones per route; the p99 figure is `posixKqueue` only. The
  much-quoted 37.8 ms routed p99 belongs to the kqueue cell whose 30,838 RPS was *discarded* in
  favour of swiftSystem's 45,664. On the backbone that produced the winning routed number the median
  p99 is **12.05 ms**. The tail was never as bad as the sentence that carried it.
- **"Level with Go" (round 1) is generous**: ours loses four of five routes (−3.1 % to −15.4 %) and
  wins one by 1.2 %.
- **"Level with the two SwiftNIO frameworks" understates us**: best local beats Hummingbird on 5/5
  and Vapor on 4/5.
- **`b0f9073` medians are garbage.** Its round 1 is the best local result ever recorded here (kqueue
  50,794–51,968 RPS at 7.3–8.3 ms p99) but rounds 2 and 3 collapse across the *whole* field (nginx
  `/payload` 8,445; Vapor `/` 15,029; hyper `/echo` 24,204). If anyone quotes this run, they must
  quote round 1 only and say so.

## And the file these supersede

`../RESULTS.md` as committed at `6133458` (2026-06-28) disagrees with all four of these runs and is
the most misleading artifact of the set. It reports absolutes roughly 3x higher (131,362 RPS on `/`
against ~44,000 here) and claims *"ours beats both SwiftNIO frameworks decisively — ~1.7–1.9x
Hummingbird's and Vapor's throughput across every scenario"*, where these runs put us at
**1.00–1.11x**. It is best-of-1 on a quiet box; these are medians of three on a loaded one. Neither
is decision-grade, and the June file carried no pointer to the July numbers.
