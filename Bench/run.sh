#!/usr/bin/env bash
#
# Bench/run.sh — comparative HTTP load battletest.
#
# Drives our `httpd-example` and any installed reference servers (nginx, Caddy, Hummingbird) with the
# same load generator (`oha`) on identical routes, and prints a side-by-side table of throughput and
# tail latency. This is the "vs the best" yardstick the campaign is measured against; the per-engine
# allocation/instruction work is locked by the in-package ordo benchmarks, this is the end-to-end one.
#
# Iron-Law note: throughput (rps) and the latency *tail* (p99/p99.9) are what users feel. We report
# percentiles, not averages, and run a fixed-duration closed-loop test per server. For a constant-rate,
# coordinated-omission-free run, set RATE (oha's --rate) — see README.md.
#
# Usage:
#   ./Bench/run.sh                       # default: route / , 64 conns, 10s, swiftSystem backbone
#   ROUTE=/health CONNECTIONS=128 DURATION=20s ./Bench/run.sh
#   SERVERS="ours nginx caddy hummingbird" ./Bench/run.sh
#
# Requires: oha (brew install oha). Optional: jq (nicer parsing), nginx, caddy, swift (Hummingbird).
#
set -uo pipefail

# --- configuration (all overridable via env) --------------------------------------------------------
DURATION="${DURATION:-10s}"          # oha -z: wall-clock duration of each run
CONNECTIONS="${CONNECTIONS:-64}"     # oha -c: concurrent connections (closed loop)
RATE="${RATE:-}"                     # oha -q per-worker rate; set for an open-loop, CO-free run
ROUTE="${ROUTE:-/}"                  # path to hit on every server
BACKBONE="${BACKBONE:-swiftSystem}"  # our transport backbone: swiftSystem|posixKqueue|posixDispatch|networkFramework
SERVERS="${SERVERS:-ours nginx caddy hummingbird}"  # which to run if present
HTTP2="${HTTP2:-0}"                  # 1 → add oha --http2 (needs TLS; see README, h2c is not oha-drivable)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/swiftpm-build/HTTP-battletest}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
mkdir -p "$RESULTS_DIR"

PORT_OURS=8080; PORT_NGINX=8081; PORT_CADDY=8082; PORT_HB=8083

# --- preflight --------------------------------------------------------------------------------------
command -v oha >/dev/null || { echo "error: 'oha' not found — brew install oha" >&2; exit 1; }
HAVE_JQ=0; command -v jq >/dev/null && HAVE_JQ=1

SERVER_PID=""
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""; }
trap cleanup EXIT INT TERM

# Wait until a server answers on $1 (url), up to ~5s; return 1 if it never comes up.
wait_ready() {
    for _ in $(seq 1 50); do
        curl -fsS -o /dev/null --max-time 1 "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# Run one oha pass against $1 (url), label $2; appends a TSV row "label\trps\tp50ms\tp99ms\tp999ms".
bench_one() {
    local url="$1" label="$2" json="$RESULTS_DIR/$2.json"
    local args=(-z "$DURATION" -c "$CONNECTIONS" --no-tui --output-format json)
    [ -n "$RATE" ] && args+=(-q "$RATE")
    [ "$HTTP2" = "1" ] && args+=(--http2)
    oha "${args[@]}" "$url" > "$json" 2>/dev/null || { echo "  $label: oha failed" >&2; return 1; }
    if [ "$HAVE_JQ" = "1" ]; then
        # oha latency percentiles are in seconds; convert to ms. Field name has varied across versions.
        local rps p50 p99 p999
        rps=$(jq -r '.summary.requestsPerSec // .summary.rps // 0' "$json")
        p50=$(jq -r '(.latencyPercentiles."p50" // .latencyPercentiles.p50 // 0)*1000' "$json")
        p99=$(jq -r '(.latencyPercentiles."p99" // .latencyPercentiles.p99 // 0)*1000' "$json")
        p999=$(jq -r '(.latencyPercentiles."p99.9" // 0)*1000' "$json")
        printf '%s\t%.0f\t%.3f\t%.3f\t%.3f\n' "$label" "$rps" "$p50" "$p99" "$p999" >> "$RESULTS_DIR/_table.tsv"
    else
        printf '%s\t(install jq to parse %s)\n' "$label" "$json" >> "$RESULTS_DIR/_table.tsv"
    fi
}

# Launch $2 (a command, backgrounded), wait for $3 (url), bench it as $1, then kill it.
run_server() {
    local label="$1" url="$3"; shift 3
    echo "→ $label …"
    "$@" >"$RESULTS_DIR/$label.server.log" 2>&1 &
    SERVER_PID=$!
    if wait_ready "$url"; then bench_one "$url" "$label"; else echo "  $label: never became ready" >&2; fi
    cleanup
    sleep 0.3  # let the port free before the next server binds
}

# --- build our server once (release — the optimizer paths the perf claims depend on) ----------------
echo "building httpd-example (release)…"
swift build -c release --package-path "$REPO_ROOT" --scratch-path "$SCRATCH" --product httpd-example \
    >"$RESULTS_DIR/_build.log" 2>&1 || { echo "error: build failed (see _build.log)" >&2; exit 1; }
OURS_BIN="$SCRATCH/release/httpd-example"

: > "$RESULTS_DIR/_table.tsv"
echo "route=$ROUTE  connections=$CONNECTIONS  duration=$DURATION  rate=${RATE:-closed-loop}  http2=$HTTP2"
echo

for s in $SERVERS; do
    case "$s" in
        ours)
            run_server "ours($BACKBONE)" "" "http://127.0.0.1:$PORT_OURS$ROUTE" \
                env HTTPD_MAX_CONN=1000000 HTTPD_QUIET=1 "$OURS_BIN" "$PORT_OURS" "$BACKBONE"
            ;;
        nginx)
            command -v nginx >/dev/null && run_server "nginx" "" "http://127.0.0.1:$PORT_NGINX$ROUTE" \
                nginx -c "$SCRIPT_DIR/servers/nginx.conf" -g "daemon off;" \
                || echo "skip nginx (not installed)"
            ;;
        caddy)
            if command -v caddy >/dev/null; then
                mkdir -p "$RESULTS_DIR/caddy-home"
                run_server "caddy" "" "http://127.0.0.1:$PORT_CADDY$ROUTE" \
                    env HOME="$RESULTS_DIR/caddy-home" XDG_DATA_HOME="$RESULTS_DIR/caddy-home" \
                    caddy run --config "$SCRIPT_DIR/servers/Caddyfile" --adapter caddyfile
            else
                echo "skip caddy (not installed)"
            fi
            ;;
        hummingbird)
            if [ -d "$SCRIPT_DIR/hummingbird" ]; then
                ( cd "$SCRIPT_DIR/hummingbird" && swift build -c release >/dev/null 2>&1 )
                HB_BIN="$SCRIPT_DIR/hummingbird/.build/release/hb-bench"
                [ -x "$HB_BIN" ] && run_server "hummingbird" "" "http://127.0.0.1:$PORT_HB$ROUTE" \
                    "$HB_BIN" "$PORT_HB" || echo "skip hummingbird (build failed)"
            else
                echo "skip hummingbird (Bench/hummingbird not present)"
            fi
            ;;
    esac
done

# --- report -----------------------------------------------------------------------------------------
echo
echo "| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |"
echo "|---|---:|---:|---:|---:|"
while IFS=$'\t' read -r label rps p50 p99 p999; do
    printf '| %s | %s | %s | %s | %s |\n' "$label" "$rps" "$p50" "$p99" "$p999"
done < "$RESULTS_DIR/_table.tsv"
echo
echo "raw oha JSON + server logs in: $RESULTS_DIR"
