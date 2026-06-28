#!/usr/bin/env bash
#
# Benchmarking/Bench/run.sh — the consolidated comparative HTTP load battletest.
#
# Drives our `httpd-example` and every installed reference server with the SAME load generator (`oha`)
# on IDENTICAL routes, and prints one side-by-side table of throughput and tail latency. This is the
# single "vs the field" yardstick; the per-engine allocation/instruction work is locked separately by
# the in-package ordo benchmarks (`swift package --package-path Benchmarking/Benchmarks benchmark`).
#
# Competitors (each run only if its toolchain/binary is present):
#   ours         — this library's httpd-example (release), backbone selectable
#   nginx        — the C reference (event-driven)
#   caddy        — Go production server
#   hummingbird  — SwiftNIO framework (in Bench/hummingbird)
#   go           — Go net/http stdlib server (Bench/go)
#   bun          — Bun.serve native server (Bench/bun)
#   rust         — hyper + tokio (Bench/rust, release)
#   django-wsgi  — Django sync views under gunicorn, workers = CPU cores (Bench/django)
#   django-asgi  — Django async views under uvicorn, workers = CPU cores (Bench/django)
#
# Iron-Law note: throughput (rps) and the latency *tail* (p99/p99.9) are what users feel. We report
# percentiles, not averages, warm up before measuring, run in release, and pin the workload. For a
# constant-rate, coordinated-omission-free run, set RATE (oha's --rate) — see README.md.
#
# Usage:
#   ./Benchmarking/Bench/run.sh                          # all present servers, route / , 64 conns, 10s
#   SERVERS="ours go bun rust" DURATION=20s ./Benchmarking/Bench/run.sh
#   ROUTE=/health CONNECTIONS=128 ./Benchmarking/Bench/run.sh
#
# Requires: oha. Optional: jq, nginx, caddy, swift, go, bun, cargo, python3.
#
set -uo pipefail

# --- configuration (all overridable via env) --------------------------------------------------------
DURATION="${DURATION:-10s}"          # oha -z: wall-clock duration of each measured run
CONNECTIONS="${CONNECTIONS:-64}"     # oha -c: concurrent connections (closed loop)
RATE="${RATE:-}"                     # oha -q per-worker rate; set for an open-loop, CO-free run
WARMUP="${WARMUP:-2s}"               # throwaway pre-measurement pass to warm caches; set 0 to skip
ROUTE="${ROUTE:-/}"                  # path to hit on every server
BACKBONE="${BACKBONE:-swiftSystem}"  # our transport: swiftSystem|posixKqueue|posixDispatch|networkFramework
HTTP2="${HTTP2:-0}"                  # 1 → HTTP/2-over-TLS run (ours/nginx/caddy only); 0 → HTTP/1.1
SERVERS="${SERVERS:-ours nginx caddy hummingbird go bun rust django-wsgi django-asgi}"

NCPU="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
DJANGO_WORKERS="${DJANGO_WORKERS:-$NCPU}"  # Django is single-thread per worker → use the whole box

# HTTP/2 here is h2-over-TLS (ALPN). Only ours/nginx/caddy carry the TLS path; the other competitors
# stay HTTP/1.1 cleartext and are skipped under HTTP2=1.
SCHEME=http
if [ "$HTTP2" = "1" ]; then
    SCHEME=https
    BACKBONE=networkFramework
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/swiftpm-build/HTTP-battletest}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
mkdir -p "$RESULTS_DIR"

PORT_OURS=8080; PORT_NGINX=8081; PORT_CADDY=8082; PORT_HB=8083
PORT_GO=8084; PORT_BUN=8085; PORT_RUST=8086; PORT_DJANGO=8087

# --- preflight --------------------------------------------------------------------------------------
command -v oha >/dev/null || { echo "error: 'oha' not found — brew install oha" >&2; exit 1; }
HAVE_JQ=0; command -v jq >/dev/null && HAVE_JQ=1

SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    # Reap any port-holding stragglers (gunicorn/uvicorn fork workers the parent PID doesn't cover).
    for p in "$@"; do
        local pids; pids=$(lsof -ti "tcp:$p" 2>/dev/null) && [ -n "$pids" ] && kill $pids 2>/dev/null
    done
    SERVER_PID=""
}
trap 'cleanup' EXIT INT TERM

# Wait until a server answers on $1 (url), up to ~8s; return 1 if it never comes up.
wait_ready() {
    for _ in $(seq 1 80); do
        curl -fksS -o /dev/null --max-time 1 "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# Run one oha pass against $1 (url), label $2; appends a TSV row "label rps p50ms p99ms p999ms".
bench_one() {
    local url="$1" label="$2" json="$RESULTS_DIR/$2.json"
    local args=(-z "$DURATION" -c "$CONNECTIONS" --no-tui --output-format json)
    [ -n "$RATE" ] && args+=(-q "$RATE")
    [ "$HTTP2" = "1" ] && args+=(--http2 --insecure)
    if [ "$WARMUP" != "0" ]; then
        local warm_args=(-z "$WARMUP" -c "$CONNECTIONS" --no-tui)
        [ "$HTTP2" = "1" ] && warm_args+=(--http2 --insecure)
        oha "${warm_args[@]}" "$url" >/dev/null 2>&1 || true
    fi
    oha "${args[@]}" "$url" > "$json" 2>/dev/null || { echo "  $label: oha failed" >&2; return 1; }
    if [ "$HAVE_JQ" = "1" ]; then
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

# Launch a backgrounded server command, wait for its URL, bench it, then tear it (and port) down.
#   run_server <label> <url> <extra-port-to-reap> -- <command...>
run_server() {
    local label="$1" url="$2" reap="$3"; shift 3
    [ "$1" = "--" ] && shift
    echo "→ $label …"
    "$@" >"$RESULTS_DIR/$label.server.log" 2>&1 &
    SERVER_PID=$!
    if wait_ready "$url"; then bench_one "$url" "$label"; else echo "  $label: never became ready" >&2; fi
    cleanup "$reap"
    sleep 0.4  # let the port free before the next server binds
}

# --- build our server once (release) ----------------------------------------------------------------
echo "building httpd-example (release)…"
swift build -c release --package-path "$REPO_ROOT" --scratch-path "$SCRATCH" --product httpd-example \
    >"$RESULTS_DIR/_build.log" 2>&1 || { echo "error: build failed (see _build.log)" >&2; exit 1; }
OURS_BIN="$SCRATCH/release/httpd-example"

# --- TLS material for the h2 run (self-signed) ------------------------------------------------------
NGINX_CONF="$SCRIPT_DIR/servers/nginx.conf"; CADDY_CONF="$SCRIPT_DIR/servers/Caddyfile"
if [ "$HTTP2" = "1" ]; then
    command -v openssl >/dev/null || { echo "error: 'openssl' needed for the h2-TLS run" >&2; exit 1; }
    CERT="$RESULTS_DIR/dev-cert.pem"; KEY="$RESULTS_DIR/dev-key.pem"
    if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
        openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 365 -nodes \
            -subj "/CN=localhost" >/dev/null 2>&1 || { echo "error: cert generation failed" >&2; exit 1; }
    fi
    NGINX_CONF="$RESULTS_DIR/nginx-tls.conf"; CADDY_CONF="$RESULTS_DIR/Caddyfile-tls"
    sed -e "s#__CERT__#$CERT#g" -e "s#__KEY__#$KEY#g" "$SCRIPT_DIR/servers/nginx-tls.conf" >"$NGINX_CONF"
    sed -e "s#__CERT__#$CERT#g" -e "s#__KEY__#$KEY#g" "$SCRIPT_DIR/servers/Caddyfile-tls" >"$CADDY_CONF"
fi

: > "$RESULTS_DIR/_table.tsv"
echo "route=$ROUTE  connections=$CONNECTIONS  duration=$DURATION  rate=${RATE:-closed-loop}  http2=$HTTP2  ncpu=$NCPU"
echo

for s in $SERVERS; do
    case "$s" in
        ours)
            ours_cmd=(env HTTPD_MAX_CONN=1000000 HTTPD_QUIET=1 "$OURS_BIN" "$PORT_OURS" "$BACKBONE")
            [ "$HTTP2" = "1" ] && ours_cmd+=(tls)
            run_server "ours($BACKBONE)" "$SCHEME://127.0.0.1:$PORT_OURS$ROUTE" "$PORT_OURS" -- "${ours_cmd[@]}"
            ;;
        nginx)
            command -v nginx >/dev/null && run_server "nginx" "$SCHEME://127.0.0.1:$PORT_NGINX$ROUTE" "$PORT_NGINX" -- \
                nginx -c "$NGINX_CONF" -g "daemon off;" || echo "skip nginx (not installed)"
            ;;
        caddy)
            if command -v caddy >/dev/null; then
                mkdir -p "$RESULTS_DIR/caddy-home"
                run_server "caddy" "$SCHEME://127.0.0.1:$PORT_CADDY$ROUTE" "$PORT_CADDY" -- \
                    env HOME="$RESULTS_DIR/caddy-home" XDG_DATA_HOME="$RESULTS_DIR/caddy-home" \
                    caddy run --config "$CADDY_CONF" --adapter caddyfile
            else echo "skip caddy (not installed)"; fi
            ;;
        hummingbird)
            if [ "$HTTP2" = "1" ]; then echo "skip hummingbird (h1-only here)"; continue; fi
            if [ -d "$SCRIPT_DIR/hummingbird" ] && command -v swift >/dev/null; then
                ( cd "$SCRIPT_DIR/hummingbird" && swift build -c release ) \
                    >"$RESULTS_DIR/hummingbird.build.log" 2>&1
                HB_BIN="$SCRIPT_DIR/hummingbird/.build/release/hb-bench"
                [ -x "$HB_BIN" ] && run_server "hummingbird" "http://127.0.0.1:$PORT_HB$ROUTE" "$PORT_HB" -- \
                    "$HB_BIN" "$PORT_HB" || echo "skip hummingbird (build failed, see hummingbird.build.log)"
            else echo "skip hummingbird (absent)"; fi
            ;;
        go)
            if [ "$HTTP2" = "1" ]; then echo "skip go (h1-only here)"; continue; fi
            if command -v go >/dev/null; then
                GO_BIN="$RESULTS_DIR/go-bench"
                ( cd "$SCRIPT_DIR/go" && go build -o "$GO_BIN" . ) >"$RESULTS_DIR/go.build.log" 2>&1
                [ -x "$GO_BIN" ] && run_server "go" "http://127.0.0.1:$PORT_GO$ROUTE" "$PORT_GO" -- \
                    "$GO_BIN" "$PORT_GO" || echo "skip go (build failed, see go.build.log)"
            else echo "skip go (not installed)"; fi
            ;;
        bun)
            if [ "$HTTP2" = "1" ]; then echo "skip bun (h1-only here)"; continue; fi
            if command -v bun >/dev/null; then
                run_server "bun" "http://127.0.0.1:$PORT_BUN$ROUTE" "$PORT_BUN" -- \
                    bun run "$SCRIPT_DIR/bun/server.js" "$PORT_BUN"
            else echo "skip bun (not installed)"; fi
            ;;
        rust)
            if [ "$HTTP2" = "1" ]; then echo "skip rust (h1-only here)"; continue; fi
            if command -v cargo >/dev/null; then
                echo "building rust-bench (release; first build downloads crates)…"
                ( cd "$SCRIPT_DIR/rust" && cargo build --release ) >"$RESULTS_DIR/rust.build.log" 2>&1
                RUST_BIN="$SCRIPT_DIR/rust/target/release/rust-bench"
                [ -x "$RUST_BIN" ] && run_server "rust" "http://127.0.0.1:$PORT_RUST$ROUTE" "$PORT_RUST" -- \
                    "$RUST_BIN" "$PORT_RUST" || echo "skip rust (build failed, see rust.build.log)"
            else echo "skip rust (cargo not installed)"; fi
            ;;
        django-wsgi|django-asgi)
            if [ "$HTTP2" = "1" ]; then echo "skip $s (h1-only here)"; continue; fi
            command -v python3 >/dev/null || { echo "skip $s (python3 absent)"; continue; }
            VENV="$SCRIPT_DIR/django/.venv"
            if [ ! -x "$VENV/bin/python" ]; then
                echo "creating Django .venv (first run; installs django/gunicorn/uvicorn)…"
                python3 -m venv "$VENV" \
                    && "$VENV/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 \
                    && "$VENV/bin/pip" install --quiet -r "$SCRIPT_DIR/django/requirements.txt" \
                        >"$RESULTS_DIR/_venv-install.log" 2>&1 \
                    || { echo "skip $s (venv/pip failed, see _venv-install.log)"; continue; }
            fi
            APP="$SCRIPT_DIR/django/djangoapp"
            if [ "$s" = "django-wsgi" ]; then
                run_server "django-wsgi" "http://127.0.0.1:$PORT_DJANGO$ROUTE" "$PORT_DJANGO" -- \
                    env PYTHONPATH="$APP" DJANGO_SETTINGS_MODULE=benchsite.settings \
                    "$VENV/bin/gunicorn" benchsite.wsgi:application \
                    --bind "127.0.0.1:$PORT_DJANGO" --workers "$DJANGO_WORKERS" --log-level error
            else
                run_server "django-asgi" "http://127.0.0.1:$PORT_DJANGO$ROUTE" "$PORT_DJANGO" -- \
                    env PYTHONPATH="$APP" DJANGO_SETTINGS_MODULE=benchsite.settings BENCH_ASYNC=1 \
                    "$VENV/bin/uvicorn" benchsite.asgi:application \
                    --host 127.0.0.1 --port "$PORT_DJANGO" --workers "$DJANGO_WORKERS" --log-level error
            fi
            ;;
        *) echo "skip $s (unknown server)";;
    esac
done

# --- report -----------------------------------------------------------------------------------------
echo
echo "| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |"
echo "|---|---:|---:|---:|---:|"
if [ -s "$RESULTS_DIR/_table.tsv" ]; then
    sort -t$'\t' -k2 -nr "$RESULTS_DIR/_table.tsv" | while IFS=$'\t' read -r label rps p50 p99 p999; do
        printf '| %s | %s | %s | %s | %s |\n' "$label" "$rps" "$p50" "$p99" "$p999"
    done
fi
echo
echo "route=$ROUTE  connections=$CONNECTIONS  duration=$DURATION  http2=$HTTP2 — raw oha JSON + logs in: $RESULTS_DIR"
