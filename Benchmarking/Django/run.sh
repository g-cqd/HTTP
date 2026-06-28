#!/usr/bin/env bash
#
# Benchmarking/Django/run.sh — the Swift HTTP server vs Django, across a matrix of use cases.
#
# Drives three servers — ours (the Swift library), Django under gunicorn (WSGI, sync views), and Django
# under uvicorn (ASGI, async views) — with the SAME load generator (oha) on IDENTICAL routes, and prints
# side-by-side throughput (rps) and tail latency (p50/p99/p99.9) per scenario.
#
# Two calibrations per scenario (chosen because Django is GIL-bound — one worker ≈ one core):
#   • ceiling      — every server uses the whole box (Django workers = CPU cores; ours multi-core),
#                    closed-loop at high concurrency. "What can each actually serve here?"
#   • efficiency   — one Django worker, one serialized connection (-c 1). Neither side benefits from
#                    extra cores, so this isolates per-request framework cost (read p50, not rps).
#
# Scenarios (each mirrored 1:1 by ours-bench and the Django app):
#   plaintext   GET  /                         framework-overhead floor
#   json        GET  /json                      serialize a small object
#   routing     GET  /hello/world?greeting=Hi   router + path/query params
#   echo        POST /echo  (JSON body)         request read + JSON round-trip
#   middleware  GET  /payload  (gzip)           realistic middleware chain on a ~1 KiB body
#
# Usage:
#   ./run.sh                                           # full matrix
#   SCENARIOS="plaintext json" CALIBRATIONS=ceiling ./run.sh
#   SERVERS="ours django-asgi" DURATION=20s ./run.sh
#
# Requires: oha, jq, swift, python3. Builds ours (release) and the .venv on first run.
#
set -uo pipefail

# --- configuration (all overridable via env) --------------------------------------------------------
DURATION="${DURATION:-10s}"                          # oha -z: measured wall-clock per run
WARMUP="${WARMUP:-3s}"                                # throwaway pre-measurement pass; 0 to skip
CEIL_CONN="${CEIL_CONN:-64}"                          # ceiling: closed-loop concurrency
EFF_CONN="${EFF_CONN:-1}"                             # efficiency: serialized (per-request latency)
NCPU="${NCPU:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"
CEIL_WORKERS="${CEIL_WORKERS:-$NCPU}"                 # Django workers for the ceiling run (≈ cores)
GUNICORN_WORKER_CLASS="${GUNICORN_WORKER_CLASS:-sync}" # 'sync' (classic) or 'gthread' (keep-alive)
SERVERS="${SERVERS:-ours django-wsgi django-asgi}"
CALIBRATIONS="${CALIBRATIONS:-ceiling efficiency}"
SCENARIOS="${SCENARIOS:-plaintext json routing echo middleware}"
PORT="${PORT:-8200}"                                  # one server at a time, so one port is reused
OURS_JSON="${OURS_JSON:-foundation}"                  # ours /json + /echo backend: foundation | adjson

ECHO_BODY='{"message":"Hello, World!","numbers":[1,2,3,4,5],"flag":true}'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DJANGO_DIR="$SCRIPT_DIR/djangoapp"
VENV="$SCRIPT_DIR/.venv"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
OURS_SCRATCH="${OURS_SCRATCH:-/tmp/swiftpm-build/ours-bench}"
OURS_BIN="$OURS_SCRATCH/release/ours-bench"
mkdir -p "$RESULTS_DIR"

# ADJSON (OURS_JSON=adjson) resolves its ADFoundation sibling from a LOCAL checkout via this env var,
# keeping the investigation "locally only" (no git fetch of the AD-family). Default: the sibling beside
# the HTTP repo (…/g-cqd/ADFoundation). Export ADFOUNDATION_PATH yourself to point elsewhere.
export ADFOUNDATION_PATH="${ADFOUNDATION_PATH:-$(cd "$SCRIPT_DIR/../../../ADFoundation" 2>/dev/null && pwd)}"

# --- preflight --------------------------------------------------------------------------------------
command -v oha >/dev/null || { echo "error: 'oha' not found — brew install oha" >&2; exit 1; }
command -v jq  >/dev/null || { echo "error: 'jq' not found — brew install jq"  >&2; exit 1; }
command -v swift >/dev/null || { echo "error: 'swift' not found" >&2; exit 1; }

echo "building ours-bench (release)…"
swift build -c release --package-path "$SCRIPT_DIR/ours" --scratch-path "$OURS_SCRATCH" \
    --product ours-bench >"$RESULTS_DIR/_ours-build.log" 2>&1 \
    || { echo "error: ours-bench build failed (see results/_ours-build.log)" >&2; exit 1; }

if [ ! -x "$VENV/bin/python" ]; then
    echo "creating .venv + installing Django/gunicorn/uvicorn…"
    python3 -m venv "$VENV" || { echo "error: venv creation failed" >&2; exit 1; }
    "$VENV/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1
    "$VENV/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt" \
        >"$RESULTS_DIR/_venv-install.log" 2>&1 \
        || { echo "error: pip install failed (see results/_venv-install.log)" >&2; exit 1; }
fi
# Sanity-check the Django app once (catches a broken settings/urls before the matrix runs).
( cd "$DJANGO_DIR" && DJANGO_SETTINGS_MODULE=benchsite.settings "$VENV/bin/python" -m django check ) \
    >"$RESULTS_DIR/_django-check.log" 2>&1 || { echo "error: 'django check' failed (see results/_django-check.log)" >&2; exit 1; }

# --- server lifecycle -------------------------------------------------------------------------------
SERVER_PID=""
COMMON_FORK_ENV=(OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES no_proxy='*')

# Launch $1 with middleware flag $2 (0/1) and worker count $3, backgrounded; sets SERVER_PID.
launch() {
    local server="$1" mw="$2" workers="$3" log="$RESULTS_DIR/$1.server.log"
    case "$server" in
        ours)  # one process, all cores; worker count is N/A (no GIL)
            # Default to the event-driven posixKqueue backbone — a flat thread count and a tight latency
            # tail under concurrency. Override with OURS_BACKBONE=swiftSystem to benchmark the blocking
            # reference (best single-connection median, but a fat p99/p99.9 tail from thread
            # oversubscription — audit 2026-06-28 tail-latency variance).
            env HTTPD_MAX_CONN=1000000 BENCH_MIDDLEWARE="$mw" BENCH_JSON="$OURS_JSON" \
                "$OURS_BIN" "$PORT" "${OURS_BACKBONE:-posixKqueue}" >"$log" 2>&1 &
            ;;
        django-wsgi)
            env "${COMMON_FORK_ENV[@]}" BENCH_MIDDLEWARE="$mw" \
                DJANGO_SETTINGS_MODULE=benchsite.settings PYTHONPATH="$DJANGO_DIR" \
                "$VENV/bin/gunicorn" benchsite.wsgi:application \
                --bind "127.0.0.1:$PORT" --workers "$workers" \
                --worker-class "$GUNICORN_WORKER_CLASS" --threads 4 \
                --graceful-timeout 2 --log-level error >"$log" 2>&1 &
            ;;
        django-asgi)
            env "${COMMON_FORK_ENV[@]}" BENCH_MIDDLEWARE="$mw" BENCH_ASYNC=1 \
                DJANGO_SETTINGS_MODULE=benchsite.settings PYTHONPATH="$DJANGO_DIR" \
                "$VENV/bin/uvicorn" benchsite.asgi:application \
                --host 127.0.0.1 --port "$PORT" --workers "$workers" \
                --timeout-graceful-shutdown 2 --log-level error >"$log" 2>&1 &
            ;;
    esac
    SERVER_PID=$!
}

stop_server() {
    [ -z "$SERVER_PID" ] && return
    # Children first (gunicorn/uvicorn workers), then the master: SIGTERM, escalate to SIGKILL after a
    # short grace so a slow graceful-shutdown can't stall the matrix (validated teardown < 1.5s).
    pkill -TERM -P "$SERVER_PID" 2>/dev/null
    kill  -TERM    "$SERVER_PID" 2>/dev/null
    for _ in $(seq 1 15); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
    pkill -KILL -P "$SERVER_PID" 2>/dev/null
    kill  -KILL    "$SERVER_PID" 2>/dev/null
    # Belt and suspenders: free the port no matter what (a worker that outlived its parent).
    local pids; pids=$(lsof -ti "tcp:$PORT" 2>/dev/null)
    [ -n "$pids" ] && kill -9 $pids 2>/dev/null
    SERVER_PID=""
    sleep 0.4
}
trap 'stop_server' EXIT INT TERM

wait_ready() {  # poll the URL until it answers (~8s budget)
    for _ in $(seq 1 80); do
        curl -fsS -o /dev/null --max-time 1 "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# --- one scenario × one server ----------------------------------------------------------------------
# scenario_path / scenario_args / scenario_mw set the request shape per scenario.
scenario_path() {
    case "$1" in
        plaintext)  echo "/" ;;
        json)       echo "/json" ;;
        routing)    echo "/hello/world?greeting=Hi" ;;
        echo)       echo "/echo" ;;
        middleware) echo "/payload" ;;
    esac
}
scenario_mw() { [ "$1" = "middleware" ] && echo 1 || echo 0; }   # which scenario needs the chain on
# Extra oha args per scenario (POST body, headers). Populates the global SARGS array.
scenario_args() {
    SARGS=()
    case "$1" in
        echo)       SARGS=(-m POST -d "$ECHO_BODY" -T "application/json") ;;
        middleware) SARGS=(-H "Accept-Encoding: gzip") ;;
    esac
}

# Run oha for $server/$scenario/$calibration; append a TSV row to _table.tsv.
bench_one() {
    local server="$1" scenario="$2" calib="$3" conn="$4"
    local url="http://127.0.0.1:$PORT$(scenario_path "$scenario")"
    local json="$RESULTS_DIR/${scenario}__${calib}__${server}.json"
    scenario_args "$scenario"

    if [ "$WARMUP" != "0" ]; then
        oha -z "$WARMUP" -c "$conn" --no-tui "${SARGS[@]}" "$url" >/dev/null 2>&1 || true
    fi
    oha -z "$DURATION" -c "$conn" --no-tui --output-format json "${SARGS[@]}" "$url" \
        >"$json" 2>/dev/null || { echo "    $server/$scenario/$calib: oha failed" >&2; return 1; }

    # oha latency percentiles are in seconds → ms. ok% = 2xx share of all responses (catches silent 5xx).
    local rps p50 p99 p999 okpct
    rps=$(jq  -r '.summary.requestsPerSec // .summary.rps // 0' "$json")
    p50=$(jq  -r '(.latencyPercentiles."p50"  // 0)*1000' "$json")
    p99=$(jq  -r '(.latencyPercentiles."p99"  // 0)*1000' "$json")
    p999=$(jq -r '(.latencyPercentiles."p99.9" // 0)*1000' "$json")
    okpct=$(jq -r '
        (.statusCodeDistribution // {}) as $d
        | ([$d | to_entries[] | select((.key|tonumber) >= 200 and (.key|tonumber) < 300) | .value] | add // 0) as $ok
        | ([$d | to_entries[] | .value] | add // 0) as $tot
        | if $tot > 0 then ($ok*100/$tot) else 0 end' "$json")
    printf '%s\t%s\t%s\t%.0f\t%.3f\t%.3f\t%.3f\t%.1f\n' \
        "$scenario" "$calib" "$server" "$rps" "$p50" "$p99" "$p999" "$okpct" >> "$RESULTS_DIR/_table.tsv"
    printf '    %-12s %-10s %-11s  %8.0f rps  p50=%.3fms p99=%.3fms ok=%.0f%%\n' \
        "$scenario" "$calib" "$server" "$rps" "$p50" "$p99" "$okpct"
}

# --- the matrix -------------------------------------------------------------------------------------
: > "$RESULTS_DIR/_table.tsv"
echo
echo "matrix: servers=[$SERVERS]  calibrations=[$CALIBRATIONS]  scenarios=[$SCENARIOS]"
echo "ncpu=$NCPU  ceiling: -c$CEIL_CONN workers=$CEIL_WORKERS  efficiency: -c$EFF_CONN workers=1"
echo "duration=$DURATION warmup=$WARMUP  gunicorn worker-class=$GUNICORN_WORKER_CLASS  ours-json=$OURS_JSON"
echo

for calib in $CALIBRATIONS; do
    if [ "$calib" = "ceiling" ]; then conn="$CEIL_CONN"; workers="$CEIL_WORKERS"
    else conn="$EFF_CONN"; workers=1; fi
    echo "═══ calibration: $calib  (-c$conn, Django workers=$workers) ══════════════════════════════"
    for server in $SERVERS; do
        # Two launches max per (server,calib): middleware off (4 scenarios) then on (1).
        for mw in 0 1; do
            # Which requested scenarios need this middleware setting?
            scen_for_mw=""
            for scenario in $SCENARIOS; do
                [ "$(scenario_mw "$scenario")" = "$mw" ] && scen_for_mw="$scen_for_mw $scenario"
            done
            [ -z "$scen_for_mw" ] && continue
            echo "  → $server (middleware=$mw, workers=$workers)…"
            launch "$server" "$mw" "$workers"
            if wait_ready "http://127.0.0.1:$PORT/"; then
                for scenario in $scen_for_mw; do bench_one "$server" "$scenario" "$calib" "$conn"; done
            else
                echo "    $server: never became ready (see results/$server.server.log)" >&2
            fi
            stop_server
        done
    done
done

# --- report -----------------------------------------------------------------------------------------
echo
echo "# Results — Swift HTTP server vs Django"
echo
for scenario in $SCENARIOS; do
    echo "## $scenario"
    echo
    echo "| calibration | server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) | ok% |"
    echo "|---|---|---:|---:|---:|---:|---:|"
    for calib in $CALIBRATIONS; do
        while IFS=$'\t' read -r sc ca sv rps p50 p99 p999 okp; do
            [ "$sc" = "$scenario" ] && [ "$ca" = "$calib" ] && \
                printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$ca" "$sv" "$rps" "$p50" "$p99" "$p999" "$okp"
        done < "$RESULTS_DIR/_table.tsv"
    done
    echo
done
echo "raw oha JSON + server logs in: $RESULTS_DIR"
