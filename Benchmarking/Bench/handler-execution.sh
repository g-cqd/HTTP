#!/usr/bin/env bash
#
# handler-execution.sh — measure HandlerExecutionPolicy against the rule pre-registered in
# docs/adr/0007-handler-execution-policy.md (2026-07-31 audit, CR-F7).
#
# This script answers exactly three questions, and no others:
#
#   1. trivial-route p50   under each policy   (rule clause 1: regression < 10%)
#   2. trivial-route rps   under each policy   (rule clause 2: regression < 5%)
#   3. trivial-route p99 under a 90/10 trivial+blocking mix
#                                              (rule clause 3: improvement > 2x)
#
# The mix is driven as a CONNECTION share rather than a request share: `oha` drives one URL, so 90
# connections hammer /exec/trivial while 10 hold /exec/block. That is the honest shape for the
# question anyway — the finding is that a handler holding a reactor thread stalls unrelated
# connections, and connection share is what decides how many reactor shards are affected.
#
# Best-of-N per cell, matching run.sh: on a colocated box a single sequential pass thermally
# throttles, so sampling each policy at N points and keeping its best cancels the ordering bias.
# Best-of-N does NOT estimate a distribution — it selects favorable noise — which is one of several
# reasons the ADR treats every number this produces as provisional.
#
# Usage:
#   Benchmarking/Bench/handler-execution.sh
#
# Environment (all optional):
#   DURATION=10s CONNECTIONS=64 MIX_TRIVIAL=90 MIX_BLOCKING=10 ROUNDS=3 WARMUP=2s
#   POLICIES="inline concurrent adaptive:1"   BACKBONE=posixKqueue
#
set -uo pipefail

DURATION="${DURATION:-10s}"
CONNECTIONS="${CONNECTIONS:-64}"
MIX_TRIVIAL="${MIX_TRIVIAL:-90}"
MIX_BLOCKING="${MIX_BLOCKING:-10}"
ROUNDS="${ROUNDS:-3}"
WARMUP="${WARMUP:-2s}"
POLICIES="${POLICIES:-inline concurrent adaptive:1}"
BACKBONE="${BACKBONE:-posixKqueue}"
PORT="${PORT:-8097}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/swiftpm-build/HTTP-battletest}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results/handler-execution}"
mkdir -p "$RESULTS_DIR"
TSV="$RESULTS_DIR/_results.tsv"
: >"$TSV"

command -v oha >/dev/null || { echo "error: oha not installed (brew install oha)" >&2; exit 1; }
command -v jq  >/dev/null || { echo "error: jq not installed (brew install jq)" >&2; exit 1; }

echo "building httpd-example (release)…"
swift build -c release --package-path "$REPO_ROOT" --scratch-path "$SCRATCH" \
    --product httpd-example >"$RESULTS_DIR/_build.log" 2>&1 \
    || { echo "error: build failed (see _build.log)" >&2; exit 1; }
BIN="$SCRATCH/release/httpd-example"

# Host qualification, recorded with the results: a run on a busy box is not decision-grade, and the
# only thing worse than a noisy number is a noisy number with no record of how noisy.
{
    echo "date:      $(date -u +%FT%TZ)"
    echo "uname:     $(uname -mrs)"
    echo "cores:     $(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN)"
    echo "loadavg:   $(uptime | sed 's/.*load averages*: //')"
    echo "settings:  duration=$DURATION connections=$CONNECTIONS mix=${MIX_TRIVIAL}/${MIX_BLOCKING}"
    echo "           rounds=$ROUNDS warmup=$WARMUP backbone=$BACKBONE"
    echo "top:"
    ps -A -o %cpu,comm -r | head -6
} | tee "$RESULTS_DIR/_host.txt"

start_server() {
    HTTPD_QUIET=1 HTTPD_MAX_CONN=1000000 HTTPD_EXEC_ROUTES=1 HTTPD_HANDLER_EXEC="$1" \
        "$BIN" "$PORT" "$BACKBONE" >"$RESULTS_DIR/server-$1.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 100); do
        curl -fsS -o /dev/null "http://127.0.0.1:$PORT/exec/trivial" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "  error: server ($1) never became ready" >&2
    return 1
}

# SIGKILL, not SIGTERM. httpd-example installs a SIGTERM handler that GRACEFULLY DRAINS, and this
# harness deliberately leaves ten connections parked inside a 10 ms blocking handler — so a polite
# stop waits on the drain deadline, and a `wait` on it hangs the run. There is nothing to preserve in
# a benchmark subject between policies, so take the descriptor away and move on.
stop_server() {
    [ -n "${SERVER_PID:-}" ] && kill -9 "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=""
    # Let the listener's TIME_WAIT sockets clear so the next policy binds the same port.
    sleep 0.6
}

# record <json> <policy> <scenario> — appends "policy<TAB>scenario<TAB>rps<TAB>p50<TAB>p99<TAB>p999"
record() {
    local json="$1" policy="$2" scenario="$3"
    local total twoxx
    total=$(jq -r '[.statusCodeDistribution[]?] | add // 0' "$json")
    twoxx=$(jq -r '[.statusCodeDistribution | to_entries[]? | select(.key|startswith("2")) | .value] | add // 0' "$json")
    if [ "${total:-0}" = "0" ] || awk "BEGIN{exit !($twoxx < 0.99 * $total)}"; then
        printf '%s\t%s\tN/A\t-\t-\t-\n' "$policy" "$scenario" >>"$TSV"; return
    fi
    printf '%s\t%s\t%.0f\t%.3f\t%.3f\t%.3f\n' "$policy" "$scenario" \
        "$(jq -r '.summary.requestsPerSec // 0' "$json")" \
        "$(jq -r '(.latencyPercentiles."p50"   // 0)*1000' "$json")" \
        "$(jq -r '(.latencyPercentiles."p99"   // 0)*1000' "$json")" \
        "$(jq -r '(.latencyPercentiles."p99.9" // 0)*1000' "$json")" >>"$TSV"
}

for round in $(seq 1 "$ROUNDS"); do
    echo "════════════════ round $round/$ROUNDS ════════════════"
    for policy in $POLICIES; do
        key="${policy//:/_}"
        echo "→ $policy"
        start_server "$policy" || { stop_server; continue; }

        # (1)+(2) trivial alone.
        oha -z "$WARMUP" -c "$CONNECTIONS" --no-tui \
            "http://127.0.0.1:$PORT/exec/trivial" >/dev/null 2>&1
        oha -z "$DURATION" -c "$CONNECTIONS" --no-tui --output-format json \
            "http://127.0.0.1:$PORT/exec/trivial" \
            >"$RESULTS_DIR/$key--trivial.json" 2>/dev/null
        record "$RESULTS_DIR/$key--trivial.json" "$policy" "trivial"

        # (3) the 90/10 mix: blocking load runs for the whole trivial pass, warmup included.
        oha -z "${WARMUP}${DURATION}" -c "$MIX_BLOCKING" --no-tui \
            "http://127.0.0.1:$PORT/exec/block" >/dev/null 2>&1 &
        MIX_PID=$!
        oha -z "$WARMUP" -c "$MIX_TRIVIAL" --no-tui \
            "http://127.0.0.1:$PORT/exec/trivial" >/dev/null 2>&1
        oha -z "$DURATION" -c "$MIX_TRIVIAL" --no-tui --output-format json \
            "http://127.0.0.1:$PORT/exec/trivial" \
            >"$RESULTS_DIR/$key--mix.json" 2>/dev/null
        record "$RESULTS_DIR/$key--mix.json" "$policy" "mix"
        kill "$MIX_PID" 2>/dev/null; wait "$MIX_PID" 2>/dev/null

        # The CPU route on its own: parallelism, reported for attribution and not gated by the rule.
        oha -z "$DURATION" -c "$CONNECTIONS" --no-tui --output-format json \
            "http://127.0.0.1:$PORT/exec/cpu" \
            >"$RESULTS_DIR/$key--cpu.json" 2>/dev/null
        record "$RESULTS_DIR/$key--cpu.json" "$policy" "cpu"

        stop_server
    done
done

echo
echo "### best-of-$ROUNDS per (policy, scenario)"
echo
for scenario in trivial mix cpu; do
    echo "#### $scenario"
    echo "| policy | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |"
    echo "|---|---:|---:|---:|---:|"
    awk -F'\t' -v s="$scenario" '$2==s {
            v = ($3=="N/A" ? -1 : $3+0)
            if (!($1 in seen) || v > best[$1]) { seen[$1]=1; best[$1]=v; row[$1]=$0 }
        } END { for (p in row) print row[p] }' "$TSV" \
        | sort \
        | while IFS=$'\t' read -r policy _ rps p50 p99 p999; do
            printf '| %s | %s | %s | %s | %s |\n' "$policy" "$rps" "$p50" "$p99" "$p999"
        done
    echo
done
echo "raw oha JSON, server logs and host qualification in: $RESULTS_DIR"
