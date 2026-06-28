#!/usr/bin/env bash
#
# Benchmarking/Bench/run.sh — the consolidated comparative HTTP load battletest.
#
# Drives our `httpd-example` and every installed reference server with the SAME load generator (`oha`)
# across a SET of route scenarios (the heavier-workload comparison), and prints side-by-side tables of
# throughput and tail latency — one per scenario, plus a throughput matrix. Each server is started once
# and run through every scenario, so the whole field is measured on an identical workload.
#
# Scenarios (the shared parity route set every programmable server implements):
#   GET /              framework floor (tiny text)
#   GET /json          serialize {"message":"Hello, World!"}
#   GET /payload       ~1 KiB compressible text (a body worth gzipping)
#   GET /hello/world   router + path/query parameter
#   POST /echo         request read + body round-trip
# nginx/caddy are static servers: they serve /, /json, /payload, /hello but not /echo (no body echo
# without a scripting module) — the harness marks unsupported cells N/A via oha's success rate.
#
# Competitors (run only if their toolchain/binary is present):
#   ours · nginx · caddy · hummingbird (SwiftNIO) · go (net/http) · bun (Bun.serve) · rust (hyper+tokio)
#   · vapor (SwiftNIO) · django-wsgi (gunicorn) · django-asgi (uvicorn)
#
# The two SwiftNIO framework packages (hummingbird, vapor) are nested inside this repo, which SwiftPM
# mis-resolves ("product not found") — so they are built from a copy outside the repo tree.
#
# Usage:
#   ./Benchmarking/Bench/run.sh                              # all present servers, all scenarios
#   SCENARIOS="GET:/ GET:/json" SERVERS="ours rust go" ./Benchmarking/Bench/run.sh
#   CONNECTIONS=128 DURATION=20s ./Benchmarking/Bench/run.sh
#
# Requires: oha. Optional: jq, nginx, caddy, swift, go, bun, cargo, python3.
#
set -uo pipefail

# --- configuration (all overridable via env) --------------------------------------------------------
DURATION="${DURATION:-10s}"
CONNECTIONS="${CONNECTIONS:-64}"
RATE="${RATE:-}"
WARMUP="${WARMUP:-2s}"
BACKBONE="${BACKBONE:-swiftSystem}"
SERVERS="${SERVERS:-ours nginx caddy hummingbird go bun rust vapor django-wsgi django-asgi}"
SCENARIOS="${SCENARIOS:-GET:/ GET:/json GET:/payload GET:/hello/world POST:/echo}"
ECHO_BODY="${ECHO_BODY:-{\"x\":1\}}"

NCPU="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
DJANGO_WORKERS="${DJANGO_WORKERS:-$NCPU}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/swiftpm-build/HTTP-battletest}"
SWIFT_PKG_WORK="${SWIFT_PKG_WORK:-/tmp/http-bench-swift}"   # nested SwiftNIO packages built here (outside the repo)
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
mkdir -p "$RESULTS_DIR"

PORT_OURS=8080; PORT_NGINX=8081; PORT_CADDY=8082; PORT_HB=8083
PORT_GO=8084; PORT_BUN=8085; PORT_RUST=8086; PORT_DJANGO=8087; PORT_VAPOR=8088

command -v oha >/dev/null || { echo "error: 'oha' not found — brew install oha" >&2; exit 1; }
HAVE_JQ=0; command -v jq >/dev/null && HAVE_JQ=1
[ "$HAVE_JQ" = 1 ] || { echo "error: 'jq' required for the scenario tables — brew install jq" >&2; exit 1; }

SERVER_PID=""
reap_port() { local pids; pids=$(lsof -ti "tcp:$1" 2>/dev/null) && [ -n "$pids" ] && kill $pids 2>/dev/null; }
cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""; }
trap 'cleanup' EXIT INT TERM

wait_ready() {
    for _ in $(seq 1 150); do   # up to ~15s: cold gunicorn/uvicorn workers import Django slowly
        curl -fksS -o /dev/null --max-time 1 "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# bench_one <url> <method> <server-label> <scenario-key> — one warmed oha pass; appends a row
# "<scenkey>\t<label>\t<rps>\t<p50>\t<p99>\t<p999>" to _results.tsv, or N/A when the route is missing
# (success rate below 99% — e.g. nginx/caddy on /echo).
bench_one() {
    local url="$1" method="$2" label="$3" key="$4"
    local json="$RESULTS_DIR/${label}__${key}.json"
    local common=(-c "$CONNECTIONS" --no-tui)
    [ -n "$RATE" ] && common+=(-q "$RATE")
    if [ "$method" = "POST" ]; then
        common+=(-m POST -d "$ECHO_BODY" -H "Content-Type: application/json")
    fi
    if [ "$WARMUP" != "0" ]; then
        oha -z "$WARMUP" "${common[@]}" "$url" >/dev/null 2>&1 || true
    fi
    oha -z "$DURATION" "${common[@]}" --output-format json "$url" >"$json" 2>/dev/null || {
        printf '%s\t%s\tN/A\t-\t-\t-\n' "$key" "$label" >>"$RESULTS_DIR/_results.tsv"; return; }
    # A route counts only when ≥99% of responses are 2xx. oha's successRate treats a 4xx/5xx as a
    # "successful" HTTP exchange, so a server that 404s a route it doesn't implement (nginx/caddy on
    # /echo) would otherwise post a bogus throughput — gate on the 2xx share instead.
    local total twoxx rps p50 p99 p999
    total=$(jq -r '[.statusCodeDistribution[]?] | add // 0' "$json")
    twoxx=$(jq -r '[.statusCodeDistribution | to_entries[]? | select(.key|startswith("2")) | .value] | add // 0' "$json")
    if [ "${total:-0}" = "0" ] || awk "BEGIN{exit !($twoxx < 0.99 * $total)}"; then
        printf '%s\t%s\tN/A\t-\t-\t-\n' "$key" "$label" >>"$RESULTS_DIR/_results.tsv"; return
    fi
    rps=$(jq -r '.summary.requestsPerSec // .summary.rps // 0' "$json")
    p50=$(jq -r '(.latencyPercentiles."p50" // 0)*1000' "$json")
    p99=$(jq -r '(.latencyPercentiles."p99" // 0)*1000' "$json")
    p999=$(jq -r '(.latencyPercentiles."p99.9" // 0)*1000' "$json")
    printf '%s\t%s\t%.0f\t%.3f\t%.3f\t%.3f\n' "$key" "$label" "$rps" "$p50" "$p99" "$p999" \
        >>"$RESULTS_DIR/_results.tsv"
}

# run_all_scenarios <label> <base-url> — drive every scenario against an already-running server.
run_all_scenarios() {
    local label="$1" base="$2" scen method path key
    for scen in $SCENARIOS; do
        method="${scen%%:*}"; path="${scen#*:}"
        key="$(printf '%s' "$path" | tr -c 'A-Za-z0-9' '_')"; [ "$path" = "/" ] && key="root"
        bench_one "$base$path" "$method" "$label" "$key"
    done
}

# Build a nested Swift package from a copy OUTSIDE the repo (SwiftPM mis-resolves a package nested in
# another package's git tree). Echoes the built binary path, or nothing on failure.
build_swift_pkg() {
    local src="$1"
    local product="$2"
    local work="$SWIFT_PKG_WORK/$product"
    local bin="$work/.build/release/$product"
    # Reuse an existing build unless a source file is newer (a cold SwiftNIO build is minutes); the
    # rebuild always happens out-of-tree because SwiftPM mis-resolves a package nested in the repo.
    if [ ! -x "$bin" ] || [ -n "$(find "$src" -name '*.swift' -newer "$bin" 2>/dev/null | head -1)" ]; then
        rm -rf "$work" && mkdir -p "$work" && cp -R "$src/." "$work/" && rm -rf "$work/.build"
        ( cd "$work" && swift build -c release ) >"$RESULTS_DIR/$product.build.log" 2>&1
    fi
    [ -x "$bin" ] && printf '%s' "$bin"
}

# --- build our server once (release; the latest state of the working tree) --------------------------
echo "building httpd-example (release)…"
swift build -c release --package-path "$REPO_ROOT" --scratch-path "$SCRATCH" --product httpd-example \
    >"$RESULTS_DIR/_build.log" 2>&1 || { echo "error: build failed (see _build.log)" >&2; exit 1; }
OURS_BIN="$SCRATCH/release/httpd-example"

# --- run-local nginx/caddy configs with the 1 KiB payload filled in ---------------------------------
PAYLOAD="$(printf 'from-scratch swift http server. %.0s' $(seq 1 32))"   # 32 × 32 B = 1024 B
NGINX_CONF="$RESULTS_DIR/nginx.run.conf"; CADDY_CONF="$RESULTS_DIR/Caddyfile.run"
sed "s#__PAYLOAD__#$PAYLOAD#g" "$SCRIPT_DIR/servers/nginx.conf" >"$NGINX_CONF"
sed "s#__PAYLOAD__#$PAYLOAD#g" "$SCRIPT_DIR/servers/Caddyfile" >"$CADDY_CONF"

: > "$RESULTS_DIR/_results.tsv"
echo "scenarios=[$SCENARIOS]  connections=$CONNECTIONS  duration=$DURATION  ncpu=$NCPU"
echo

for s in $SERVERS; do
    SERVER_PID=""
    case "$s" in
        ours)
            echo "→ ours($BACKBONE) …"
            env HTTPD_MAX_CONN=1000000 HTTPD_QUIET=1 "$OURS_BIN" "$PORT_OURS" "$BACKBONE" \
                >"$RESULTS_DIR/ours.server.log" 2>&1 &
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_OURS/" \
                && run_all_scenarios "ours($BACKBONE)" "http://127.0.0.1:$PORT_OURS" \
                || echo "  ours: never ready"
            cleanup; reap_port "$PORT_OURS" ;;
        nginx)
            command -v nginx >/dev/null || { echo "skip nginx"; continue; }
            echo "→ nginx …"
            nginx -c "$NGINX_CONF" -g "daemon off;" >"$RESULTS_DIR/nginx.server.log" 2>&1 &
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_NGINX/" \
                && run_all_scenarios "nginx" "http://127.0.0.1:$PORT_NGINX" || echo "  nginx: never ready"
            cleanup; reap_port "$PORT_NGINX" ;;
        caddy)
            command -v caddy >/dev/null || { echo "skip caddy"; continue; }
            echo "→ caddy …"; mkdir -p "$RESULTS_DIR/caddy-home"
            env HOME="$RESULTS_DIR/caddy-home" XDG_DATA_HOME="$RESULTS_DIR/caddy-home" \
                caddy run --config "$CADDY_CONF" --adapter caddyfile >"$RESULTS_DIR/caddy.server.log" 2>&1 &
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_CADDY/" \
                && run_all_scenarios "caddy" "http://127.0.0.1:$PORT_CADDY" || echo "  caddy: never ready"
            cleanup; reap_port "$PORT_CADDY" ;;
        hummingbird)
            command -v swift >/dev/null || { echo "skip hummingbird"; continue; }
            echo "building hummingbird (out-of-tree)…"
            HB_BIN="$(build_swift_pkg "$SCRIPT_DIR/hummingbird" hb-bench)"
            [ -n "$HB_BIN" ] || { echo "skip hummingbird (build failed, see hb-bench.build.log)"; continue; }
            echo "→ hummingbird …"; "$HB_BIN" "$PORT_HB" >"$RESULTS_DIR/hummingbird.server.log" 2>&1 &
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_HB/" \
                && run_all_scenarios "hummingbird" "http://127.0.0.1:$PORT_HB" || echo "  hummingbird: never ready"
            cleanup; reap_port "$PORT_HB" ;;
        vapor)
            command -v swift >/dev/null || { echo "skip vapor"; continue; }
            echo "building vapor (out-of-tree)…"
            VAPOR_BIN="$(build_swift_pkg "$SCRIPT_DIR/vapor" vapor-bench)"
            [ -n "$VAPOR_BIN" ] || { echo "skip vapor (build failed, see vapor-bench.build.log)"; continue; }
            echo "→ vapor …"; "$VAPOR_BIN" "$PORT_VAPOR" >"$RESULTS_DIR/vapor.server.log" 2>&1 &
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_VAPOR/" \
                && run_all_scenarios "vapor" "http://127.0.0.1:$PORT_VAPOR" || echo "  vapor: never ready"
            cleanup; reap_port "$PORT_VAPOR" ;;
        go)
            command -v go >/dev/null || { echo "skip go"; continue; }
            GO_BIN="$RESULTS_DIR/go-bench"
            ( cd "$SCRIPT_DIR/go" && go build -o "$GO_BIN" . ) >"$RESULTS_DIR/go.build.log" 2>&1
            [ -x "$GO_BIN" ] || { echo "skip go (build failed)"; continue; }
            echo "→ go …"; "$GO_BIN" "$PORT_GO" >"$RESULTS_DIR/go.server.log" 2>&1 &
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_GO/" \
                && run_all_scenarios "go" "http://127.0.0.1:$PORT_GO" || echo "  go: never ready"
            cleanup; reap_port "$PORT_GO" ;;
        bun)
            command -v bun >/dev/null || { echo "skip bun"; continue; }
            echo "→ bun …"; bun run "$SCRIPT_DIR/bun/server.js" "$PORT_BUN" >"$RESULTS_DIR/bun.server.log" 2>&1 &
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_BUN/" \
                && run_all_scenarios "bun" "http://127.0.0.1:$PORT_BUN" || echo "  bun: never ready"
            cleanup; reap_port "$PORT_BUN" ;;
        rust)
            command -v cargo >/dev/null || { echo "skip rust"; continue; }
            echo "building rust (release)…"
            ( cd "$SCRIPT_DIR/rust" && cargo build --release ) >"$RESULTS_DIR/rust.build.log" 2>&1
            RUST_BIN="$SCRIPT_DIR/rust/target/release/rust-bench"
            [ -x "$RUST_BIN" ] || { echo "skip rust (build failed)"; continue; }
            echo "→ rust …"; "$RUST_BIN" "$PORT_RUST" >"$RESULTS_DIR/rust.server.log" 2>&1 &
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_RUST/" \
                && run_all_scenarios "rust" "http://127.0.0.1:$PORT_RUST" || echo "  rust: never ready"
            cleanup; reap_port "$PORT_RUST" ;;
        django-wsgi|django-asgi)
            command -v python3 >/dev/null || { echo "skip $s (python3 absent)"; continue; }
            VENV="$SCRIPT_DIR/django/.venv"
            if [ ! -x "$VENV/bin/python" ]; then
                echo "creating Django .venv…"
                python3 -m venv "$VENV" \
                    && "$VENV/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 \
                    && "$VENV/bin/pip" install --quiet -r "$SCRIPT_DIR/django/requirements.txt" \
                        >"$RESULTS_DIR/_venv-install.log" 2>&1 \
                    || { echo "skip $s (venv/pip failed)"; continue; }
            fi
            APP="$SCRIPT_DIR/django/djangoapp"
            echo "→ $s …"
            if [ "$s" = "django-wsgi" ]; then
                env PYTHONPATH="$APP" DJANGO_SETTINGS_MODULE=benchsite.settings \
                    "$VENV/bin/gunicorn" benchsite.wsgi:application \
                    --bind "127.0.0.1:$PORT_DJANGO" --workers "$DJANGO_WORKERS" --log-level error \
                    >"$RESULTS_DIR/$s.server.log" 2>&1 &
            else
                env PYTHONPATH="$APP" DJANGO_SETTINGS_MODULE=benchsite.settings BENCH_ASYNC=1 \
                    "$VENV/bin/uvicorn" benchsite.asgi:application \
                    --host 127.0.0.1 --port "$PORT_DJANGO" --workers "$DJANGO_WORKERS" --log-level error \
                    >"$RESULTS_DIR/$s.server.log" 2>&1 &
            fi
            SERVER_PID=$!
            wait_ready "http://127.0.0.1:$PORT_DJANGO/" \
                && run_all_scenarios "$s" "http://127.0.0.1:$PORT_DJANGO" || echo "  $s: never ready"
            cleanup; reap_port "$PORT_DJANGO" ;;
        *) echo "skip $s (unknown)";;
    esac
    sleep 0.4
done

# --- report: one table per scenario (sorted by rps), then a throughput matrix -----------------------
echo
SCEN_KEYS=""
for scen in $SCENARIOS; do
    path="${scen#*:}"; key="$(printf '%s' "$path" | tr -c 'A-Za-z0-9' '_')"; [ "$path" = "/" ] && key="root"
    SCEN_KEYS="$SCEN_KEYS $key:$scen"
done
for entry in $SCEN_KEYS; do
    key="${entry%%:*}"; scen="${entry#*:}"
    echo "### $scen"
    echo "| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |"
    echo "|---|---:|---:|---:|---:|"
    awk -F'\t' -v k="$key" '$1==k {print}' "$RESULTS_DIR/_results.tsv" \
        | sort -t$'\t' -k3 -nr \
        | while IFS=$'\t' read -r _ label rps p50 p99 p999; do
            printf '| %s | %s | %s | %s | %s |\n' "$label" "$rps" "$p50" "$p99" "$p999"
        done
    echo
done
echo "connections=$CONNECTIONS  duration=$DURATION — raw oha JSON + server logs in: $RESULTS_DIR"
