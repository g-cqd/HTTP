#!/usr/bin/env bash
#
# Benchmarking/Bench/selftest.sh — tests for the harness's own decision logic.
#
# A benchmark harness that has never been tested is an opinion. Three of the four gates that make
# `run.sh` defensible are PURE FUNCTIONS over a table — the byte-equivalence verdict, the load-drift
# verdict, and the median aggregation — precisely so that they can be exercised here without a
# server, a network, or a stable machine. This file is the red-then-green record for them:
#
#   * `parity_verdict` must FAIL a table where two subjects return different digests for one route,
#     and must not be fooled by a subject that simply does not implement the route.
#   * `host_round_verdict` must grade EXTERNAL load only: it must not reject a round for the
#     benchmark's own saturation, must reject a box that was busy before the run started, and must
#     mark external demand that appears or moves mid-round.
#   * `report_aggregate` must report the MEDIAN, must ignore rounds the drift gate excluded, and
#     must carry min/max so a wildly unstable cell is visible.
#
# Run: ./Benchmarking/Bench/selftest.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/host.sh
. "$SCRIPT_DIR/lib/host.sh"
# shellcheck source=lib/parity.sh
. "$SCRIPT_DIR/lib/parity.sh"
# shellcheck source=lib/report.sh
. "$SCRIPT_DIR/lib/report.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASSED=0; FAILED=0
TAB="$(printf '\t')"

check() {  # check <name> <expected> <actual>
    if [ "$2" = "$3" ]; then
        PASSED=$((PASSED + 1)); printf '  ok   %s\n' "$1"
    else
        FAILED=$((FAILED + 1)); printf '  FAIL %s\n       expected [%s]\n       actual   [%s]\n' "$1" "$2" "$3"
    fi
}

echo "── parity_verdict ──"

# The real defect this gate exists to catch: `GET /` answered with a per-server greeting. These are
# the actual bodies and lengths from the field before the fix.
cat >"$WORK/mismatch.tsv" <<EOF
root${TAB}rust:floor${TAB}ok${TAB}30${TAB}aaaaaaaaaaaaaaaa${TAB}text/plain
root${TAB}go:floor${TAB}ok${TAB}28${TAB}bbbbbbbbbbbbbbbb${TAB}text/plain
root${TAB}ours(swiftSystem):floor${TAB}ok${TAB}71${TAB}cccccccccccccccc${TAB}text/plain
EOF
parity_verdict "$WORK/mismatch.tsv" >"$WORK/out.tsv"; status=$?
check "differing bodies -> non-zero exit" "1" "$status"
check "differing bodies -> FAIL row" "FAIL" "$(awk -F'\t' '$1=="root"{print $2}' "$WORK/out.tsv")"
check "differing bodies -> 3 distinct digests" "3" "$(awk -F'\t' '$1=="root"{print $3}' "$WORK/out.tsv")"

cat >"$WORK/match.tsv" <<EOF
_plaintext${TAB}rust:floor${TAB}ok${TAB}13${TAB}dddddddddddddddd${TAB}text/plain
_plaintext${TAB}go:floor${TAB}ok${TAB}13${TAB}dddddddddddddddd${TAB}text/plain
_plaintext${TAB}ours(swiftSystem):full${TAB}ok${TAB}13${TAB}dddddddddddddddd${TAB}text/plain
EOF
parity_verdict "$WORK/match.tsv" >"$WORK/out.tsv"; status=$?
check "identical bodies -> zero exit" "0" "$status"
check "identical bodies -> PASS row" "PASS" "$(awk -F'\t' '{print $2}' "$WORK/out.tsv")"

# nginx does not implement POST /echo. That is not a parity failure; it is an absent cell.
cat >"$WORK/partial.tsv" <<EOF
_echo${TAB}rust:floor${TAB}ok${TAB}8${TAB}eeeeeeeeeeeeeeee${TAB}application/json
_echo${TAB}ours(posixKqueue):floor${TAB}ok${TAB}8${TAB}eeeeeeeeeeeeeeee${TAB}application/json
_echo${TAB}nginx:floor${TAB}unimplemented${TAB}0${TAB}-${TAB}-
EOF
parity_verdict "$WORK/partial.tsv" >"$WORK/out.tsv"; status=$?
check "unimplemented route is excluded, not failed" "0" "$status"

# A subject that gzips while the field returns identity — the oha default-Accept-Encoding defect.
cat >"$WORK/gzip.tsv" <<EOF
_payload${TAB}go:floor${TAB}ok${TAB}1024${TAB}1111111111111111${TAB}text/plain
_payload${TAB}ours(swiftSystem):full${TAB}ok${TAB}52${TAB}2222222222222222${TAB}text/plain
EOF
parity_verdict "$WORK/gzip.tsv" >/dev/null; status=$?
check "a gzipped body against identity peers -> FAIL" "1" "$status"

echo "── host_external_cpu ──"

# The gate must grade EXTERNAL load only. The benchmark's own tree — run.sh (pid 100 here), `oha`
# (101) and the server under test (102, a child of 101's shell) — saturates cores BY DESIGN and must
# not count. Neither must kernel_task (pid 0): its time is spent servicing whatever workload is
# running, i.e. it tracks our own load. External here: launchd (0.5 %) and two agent worktrees
# burning 455 % + 448 % — 903.5 % over 10 cores = 0.9035 busy-per-CPU.
cat >"$WORK/ps.txt" <<EOF
    0     0 120.0
    1     0   0.5
  100     1   1.2
  101   100 640.0
  102   101 310.0
  200     1 455.0
  201   200 448.0
EOF
check "the benchmark's own process tree is not external load" "0.9035" \
    "$(host_external_cpu_from_table 100 10 <"$WORK/ps.txt")"
check "kernel_task is not external load" "0.0000" \
    "$(printf '    0     0 120.0\n' | host_external_cpu_from_table 100 10)"
check "an empty process table reads zero" "0.0000" \
    "$(printf '' | host_external_cpu_from_table 100 10)"

echo "── host_round_verdict ──"

# The 2026-08-02 defect: a single-subject run on an idle box read load 1.54 → 10.63 — all of it
# self-inflicted, gone within 90 s of the run ending — and every round graded `contended`, so
# `clean` was structurally unreachable and the grade stopped distinguishing a quiet host from a
# poisoned one. Verdict args: baseline-load1, ext-start, ext-end, drift-max, ncpu, ceiling.
check "self-inflicted saturation on an idle box is clean" "clean" \
    "$(host_round_verdict 1.54 0.02 0.05 0.25 10 0.5)"
# The run the gate was built to reject: one-minute load already 16.77 on 10 cores BEFORE the
# harness built or started anything. Raising the ceiling instead of fixing the signal would have
# let this box back in; the baseline check must keep it out regardless of what `ps` says later.
check "a box already at load 16.77 stays rejected" "contended" \
    "$(host_round_verdict 16.77 0.02 0.05 0.25 10 0.5)"
check "external demand above the ceiling is contended" "contended" \
    "$(host_round_verdict 0.80 0.55 0.60 0.25 10 0.5)"
check "external load that moves mid-round is drifted" "drifted" \
    "$(host_round_verdict 0.80 0.05 0.35 0.25 10 0.5)"
check "moving and saturated is both" "drifted+contended" \
    "$(host_round_verdict 16.77 0.30 0.60 0.25 10 0.5)"
check "external load at exactly the ceiling is clean" "clean" \
    "$(host_round_verdict 5.0 0.50 0.50 0.25 10 0.5)"
check "ext drift is an absolute movement" "0.3000" "$(host_ext_drift 0.35 0.05)"

echo "── report_aggregate ──"
# Three rounds of one cell: 100, 300, 200. The median is 200; best-of-N would report 300.
cat >"$WORK/samples.tsv" <<EOF
round${TAB}subject${TAB}mode${TAB}scenkey${TAB}scenario${TAB}rps${TAB}p50${TAB}p99${TAB}p999${TAB}status
1${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}100${TAB}1${TAB}10${TAB}20${TAB}ok
2${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}300${TAB}3${TAB}30${TAB}60${TAB}ok
3${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}200${TAB}2${TAB}20${TAB}40${TAB}ok
EOF
row="$(report_aggregate "$WORK/samples.tsv" "1 2 3")"
check "reports the median, not the best" "200" "$(printf '%s' "$row" | cut -f5)"
check "carries the min across rounds" "100" "$(printf '%s' "$row" | cut -f6)"
check "carries the max across rounds" "300" "$(printf '%s' "$row" | cut -f7)"
check "medians the tail too" "20.000" "$(printf '%s' "$row" | cut -f9)"

# Round 2 excluded by the drift gate: the median of {100, 200} is 150.
row="$(report_aggregate "$WORK/samples.tsv" "1 3")"
check "an excluded round does not reach the median" "150" "$(printf '%s' "$row" | cut -f5)"
check "an excluded round is not counted" "2" "$(printf '%s' "$row" | cut -f4)"

cat >"$WORK/na.tsv" <<EOF
round${TAB}subject${TAB}mode${TAB}scenkey${TAB}scenario${TAB}rps${TAB}p50${TAB}p99${TAB}p999${TAB}status
1${TAB}nginx${TAB}floor${TAB}_echo${TAB}-${TAB}0${TAB}0${TAB}0${TAB}0${TAB}na
EOF
check "a route no round measured is na" "na" "$(report_aggregate "$WORK/na.tsv" "1" | cut -f11)"

check "stat_median of an even count interpolates" "150.000" "$(stat_median 100 200)"
check "stat_median of an odd count picks the middle" "200.000" "$(stat_median 300 100 200)"

echo "── report_spread_max ──"
# The counter-signal beside the grade: the 2026-08-02 rounds all graded NOT-clean while every
# cell's max/min spread sat at 1.01–1.03 — evidence worth reporting beside the verdict. It must
# never OVERRIDE the verdict (a uniformly slow contended box has a tight spread too).
cat >"$WORK/agg.tsv" <<EOF
ours${TAB}floor${TAB}_json${TAB}3${TAB}200${TAB}100${TAB}300${TAB}1${TAB}1${TAB}1${TAB}ok
rust${TAB}floor${TAB}_json${TAB}3${TAB}205${TAB}200${TAB}210${TAB}1${TAB}1${TAB}1${TAB}ok
nginx${TAB}floor${TAB}_echo${TAB}0${TAB}-${TAB}-${TAB}-${TAB}-${TAB}-${TAB}-${TAB}na
EOF
check "spread counter-signal picks the widest cell" "3.00" "$(report_spread_max "$WORK/agg.tsv")"
printf 'nginx\tfloor\t_echo\t0\t-\t-\t-\t-\t-\t-\tna\n' >"$WORK/agg-na.tsv"
check "spread counter-signal over only-na cells is absent" "-" \
    "$(report_spread_max "$WORK/agg-na.tsv")"

echo "── report_paired ──"
# Three rounds. The box halves in speed at round 3, hitting BOTH profiles equally. The paired ratio
# is 0.90 in every round; the ratio of the two medians is 900/1000 = 0.90 here only because the
# drift is symmetric — the next fixture shows where that estimator breaks.
cat >"$WORK/paired.tsv" <<EOF
round${TAB}subject${TAB}mode${TAB}scenkey${TAB}scenario${TAB}rps${TAB}p50${TAB}p99${TAB}p999${TAB}status
1${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}1000${TAB}1${TAB}1${TAB}1${TAB}ok
1${TAB}ours${TAB}full${TAB}_json${TAB}-${TAB}900${TAB}1${TAB}1${TAB}1${TAB}ok
2${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}2000${TAB}1${TAB}1${TAB}1${TAB}ok
2${TAB}ours${TAB}full${TAB}_json${TAB}-${TAB}1800${TAB}1${TAB}1${TAB}1${TAB}ok
3${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}500${TAB}1${TAB}1${TAB}1${TAB}ok
3${TAB}ours${TAB}full${TAB}_json${TAB}-${TAB}450${TAB}1${TAB}1${TAB}1${TAB}ok
EOF
row="$(report_paired "$WORK/paired.tsv" "1 2 3")"
check "paired ratio survives a 4x swing in the host" "0.9000" "$(printf '%s' "$row" | cut -f4)"
check "paired ratio counts the rounds it used" "3" "$(printf '%s' "$row" | cut -f3)"
check "sign count sees full slower in every round" "3" "$(printf '%s' "$row" | cut -f7)"

# Where the ratio of medians breaks: the host is slow exactly when `full` is measured. Ratio of
# medians = 1000/1000 = 1.00 and reports the chain as free; the paired ratio still reports 0.90.
cat >"$WORK/skewed.tsv" <<EOF
round${TAB}subject${TAB}mode${TAB}scenkey${TAB}scenario${TAB}rps${TAB}p50${TAB}p99${TAB}p999${TAB}status
1${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}1000${TAB}1${TAB}1${TAB}1${TAB}ok
1${TAB}ours${TAB}full${TAB}_json${TAB}-${TAB}900${TAB}1${TAB}1${TAB}1${TAB}ok
2${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}1000${TAB}1${TAB}1${TAB}1${TAB}ok
2${TAB}ours${TAB}full${TAB}_json${TAB}-${TAB}900${TAB}1${TAB}1${TAB}1${TAB}ok
3${TAB}ours${TAB}floor${TAB}_json${TAB}-${TAB}1200${TAB}1${TAB}1${TAB}1${TAB}ok
3${TAB}ours${TAB}full${TAB}_json${TAB}-${TAB}1080${TAB}1${TAB}1${TAB}1${TAB}ok
EOF
check "paired ratio is immune to which profile caught the fast round" "0.9000" \
    "$(report_paired "$WORK/skewed.tsv" "1 2 3" | cut -f4)"

# A subject measured in only one profile has no pair and must produce no row at all.
cat >"$WORK/unpaired.tsv" <<EOF
round${TAB}subject${TAB}mode${TAB}scenkey${TAB}scenario${TAB}rps${TAB}p50${TAB}p99${TAB}p999${TAB}status
1${TAB}rust${TAB}floor${TAB}_json${TAB}-${TAB}1000${TAB}1${TAB}1${TAB}1${TAB}ok
EOF
check "a peer with no full profile produces no paired row" "0" \
    "$(report_paired "$WORK/unpaired.tsv" "1" | wc -l | tr -d ' ')"

echo
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
