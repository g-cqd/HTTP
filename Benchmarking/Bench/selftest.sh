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
#   * `host_round_verdict` must mark a round whose load moved, must mark a round on a busy box, and
#     must not reject a quiet box for a large RELATIVE move between two tiny load figures.
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

echo "── host_round_verdict ──"
check "steady busy-free round is clean" "clean" "$(host_round_verdict 2.0 2.1 0.25 10 0.5)"
check "load that doubles mid-round is drifted" "drifted" "$(host_round_verdict 2.0 4.0 0.25 10 0.5)"
# 0.05 -> 0.30 is a 500 % RELATIVE move and thermally irrelevant; the floor of 1.0 must absorb it.
check "tiny absolute move on an idle box is clean" "clean" "$(host_round_verdict 0.05 0.30 0.25 10 0.5)"
check "steady but saturated box is contended" "contended" "$(host_round_verdict 8.0 8.2 0.25 10 0.5)"
check "moving and saturated is both" "drifted+contended" "$(host_round_verdict 6.0 16.0 0.25 10 0.5)"
check "drift fraction is normalised" "1.0000" "$(host_drift_fraction 2.0 4.0)"

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

echo
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
