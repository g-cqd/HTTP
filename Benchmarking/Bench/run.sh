#!/usr/bin/env bash
#
# Benchmarking/Bench/run.sh — the comparative HTTP load battletest, two-mode matrix.
#
# Drives `httpd-example` and every installed reference server with the same load generator (`oha`)
# across a set of route scenarios, and reports the MEDIAN of N rounds per cell.
#
# ── WHAT THIS HARNESS FIXES, AND WHY IT HAD TO ────────────────────────────────────────────────────
#
# Three rounds of this comparison have been run. None of them could support a conclusion, and the
# reasons were all in the harness rather than in any server:
#
#  1. TWO DIFFERENT PROGRAMS WERE COMPARED. Our example ran its full production middleware chain
#     (metrics, gzip, security headers, CORS, conditional GET with a CRC32 ETag, Date, Server, Range)
#     while every peer ran a framework-floor handler. "N % behind hyper" was therefore a sentence
#     about two different workloads. FIXED: `HTTPD_PROFILE=floor` strips our chain to the router, and
#     the matrix runs BOTH modes. The floor column is the one comparable to a peer; the full column
#     is what you deploy; the difference between them prices the chain, which nothing in this
#     repository had ever measured.
#
#  2. THE SERVERS WERE NOT ANSWERING THE SAME THING. `GET /` returned each server's own name — 30 B
#     from hyper, 28 B from Go, 71 B from us — and was reported as "framework floor" throughput for
#     the whole field. Worse, `oha` sends `accept-encoding: gzip, compress, deflate, br` by default,
#     so our CompressionMiddleware gzipped bodies that every peer returned as identity. FIXED: a
#     byte-equivalence gate runs BEFORE any timing (lib/parity.sh), `/` is replaced by a `/plaintext`
#     route that is identical on every server, and the content coding is pinned (`ACCEPT_ENCODING`,
#     default `identity`) so every server is measured putting the same bytes on the wire.
#
#  3. A FIXED SERVER ORDER ON A MOVING HOST. Every round drove the field in the same sequence, on a
#     box whose one-minute load moved 5.31 -> 16.77 between two of the rounds with unrelated work at
#     ~140 % CPU. Whatever ran last was penalised, consistently. FIXED: the order is shuffled per
#     round from a recorded seed, and the host state is sampled at the start and the end of every
#     round into the results file (lib/host.sh); a round whose load drifts past `LOAD_DRIFT_MAX` is
#     marked and dropped from the headline aggregate when a clean round exists to replace it.
#
#  4. TWO STATISTICS, NEVER STATED TOGETHER. The committed RESULTS.md was best-of-1; the two reviews
#     hand-recomputed medians of 3. That alone can explain a double-digit difference between rounds.
#     FIXED: median of N, stated in the header and in every rendered table, with the per-cell min/max
#     spread printed beside it. There is no best-of anywhere in this harness.
#
#  5. NOTHING WAS MACHINE-READABLE. FIXED: `results/results.json` carries the config, the host
#     samples, the parity digests, every individual sample and the aggregate, so two runs can be
#     compared without re-reading prose.
#
# ── USAGE ─────────────────────────────────────────────────────────────────────────────────────────
#
#   ./Benchmarking/Bench/run.sh                                    # full field, both modes, 3 rounds
#   SERVERS="ours rust go" ROUNDS=5 ./Benchmarking/Bench/run.sh
#   MODES=floor ./Benchmarking/Bench/run.sh                        # apples-to-apples column only
#   SERVERS=ours MODES=full ACCEPT_ENCODING="gzip, deflate, br" ./Benchmarking/Bench/run.sh
#   ./Benchmarking/Bench/selftest.sh                               # the harness's own tests
#
# Requires: oha, jq, curl. Optional: nginx, caddy, swift, go, bun, cargo, python3.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=lib/host.sh
. "$SCRIPT_DIR/lib/host.sh"
# shellcheck source=lib/parity.sh
. "$SCRIPT_DIR/lib/parity.sh"
# shellcheck source=lib/report.sh
. "$SCRIPT_DIR/lib/report.sh"

# --- configuration (all overridable via env) --------------------------------------------------------
DURATION="${DURATION:-5s}"
WARMUP="${WARMUP:-1s}"
CONNECTIONS="${CONNECTIONS:-64}"
RATE="${RATE:-}"
# Three rounds is the minimum that yields a true median (an odd count needs no interpolation) while
# keeping a full-field run inside a few minutes. Raise it; do not lower it below 3.
ROUNDS="${ROUNDS:-3}"
# The two-mode axis. `floor` = router only for us / framework-floor handler for a peer. `full` = our
# shipped middleware chain. Only `ours` implements `full` — see `subject_modes` for why.
MODES="${MODES:-floor full}"
BACKBONES="${BACKBONES:-posixKqueue swiftSystem}"
SERVERS="${SERVERS:-ours rust go bun hummingbird vapor nginx caddy}"
# `/plaintext`, not `/`: every server answers `/` with its own name, so `/` is not a comparable route
# and the parity gate rejects it. See lib/parity.sh.
SCENARIOS="${SCENARIOS:-GET:/plaintext GET:/json GET:/payload GET:/hello/world POST:/echo}"
ECHO_BODY="${ECHO_BODY:-{\"x\":1\}}"
# Pinned so every server puts the SAME BYTES on the wire. oha's default sends four codings, which
# makes our full profile gzip while every peer returns identity — a different payload and a cost no
# peer pays. Set this to a real negotiation list to price content coding as its own question.
ACCEPT_ENCODING="${ACCEPT_ENCODING:-identity}"
# Load-drift gate. A round whose one-minute load moves more than this fraction (normalised against a
# floor of 1.0) is marked `drifted`; a round whose load per CPU exceeds the ceiling is `contended`.
LOAD_DRIFT_MAX="${LOAD_DRIFT_MAX:-0.25}"
LOAD_CEILING_PER_CPU="${LOAD_CEILING_PER_CPU:-0.5}"
# Byte-equivalence is a hard gate by default. Setting this to 0 records the mismatch and continues —
# for diagnosing WHICH server disagrees, never for producing a number anyone quotes.
PARITY_ENFORCE="${PARITY_ENFORCE:-1}"
SEED="${SEED:-$RANDOM}"

NCPU="$(host_ncpu)"
DJANGO_WORKERS="${DJANGO_WORKERS:-$NCPU}"
SCRATCH="${SCRATCH:-/tmp/swiftpm-build/HTTP-battletest}"
SWIFT_PKG_WORK="${SWIFT_PKG_WORK:-/tmp/http-bench-swift}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
PARITY_DIR="$RESULTS_DIR/parity"
SAMPLES_TSV="$RESULTS_DIR/_samples.tsv"
ROUNDS_TSV="$RESULTS_DIR/_rounds.tsv"
mkdir -p "$RESULTS_DIR" "$PARITY_DIR"

PORT_OURS=8080; PORT_NGINX=8081; PORT_CADDY=8082; PORT_HB=8083
PORT_GO=8084; PORT_BUN=8085; PORT_RUST=8086; PORT_DJANGO=8087; PORT_VAPOR=8088

for tool in oha jq curl; do
    command -v "$tool" >/dev/null || { echo "error: '$tool' not found — brew install $tool" >&2; exit 1; }
done

SERVER_PID=""
reap_port() { local pids; pids=$(lsof -ti "tcp:$1" 2>/dev/null) && [ -n "$pids" ] && kill $pids 2>/dev/null; }
stop_server() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""; }
trap 'stop_server' EXIT INT TERM

wait_ready() {
    for _ in $(seq 1 150); do   # up to ~15s: cold gunicorn/uvicorn workers import Django slowly
        curl -fksS -o /dev/null --max-time 1 "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# --- the subject matrix ------------------------------------------------------------------------------
# A SUBJECT is one measurable configuration: "<kind>:<backbone>:<mode>". `ours` expands to one subject
# per backbone per mode; every other server contributes one subject per supported mode.

# subject_modes <kind> — which of MODES this kind can honestly run.
#
# Only `ours` runs `full`, and that is deliberate. `full` means OUR middleware chain; a peer has no
# such thing. Re-implementing an equivalent stack in Rust/Go/JS would replace a measured confound
# with an unprovable claim of equivalence — the exact failure this harness exists to end. Running a
# peer's OWN middleware instead would answer a different question ("is Hummingbird's gzip faster than
# ours?"), which is worth asking and is not this. So the peers define the floor, we are measured
# against them at the floor, and our full column is priced against our own floor.
subject_modes() {
    case "$1" in
        ours) printf '%s' "$MODES" ;;
        *) printf '%s' "$MODES" | tr ' ' '\n' | grep -x floor | tr '\n' ' ' ;;
    esac
}

subject_label() {
    local kind="${1%%:*}" rest="${1#*:}" backbone
    backbone="${rest%%:*}"
    if [ -n "$backbone" ]; then printf 'ours(%s)' "$backbone"; else printf '%s' "$kind"; fi
}
subject_mode() { printf '%s' "${1##*:}"; }
subject_kind() { printf '%s' "${1%%:*}"; }

subject_port() {
    case "$(subject_kind "$1")" in
        ours) printf '%s' "$PORT_OURS" ;; nginx) printf '%s' "$PORT_NGINX" ;;
        caddy) printf '%s' "$PORT_CADDY" ;; hummingbird) printf '%s' "$PORT_HB" ;;
        go) printf '%s' "$PORT_GO" ;; bun) printf '%s' "$PORT_BUN" ;;
        rust) printf '%s' "$PORT_RUST" ;; vapor) printf '%s' "$PORT_VAPOR" ;;
        *) printf '%s' "$PORT_DJANGO" ;;
    esac
}

# subject_start <id> — launch it in the background and set SERVER_PID; returns non-zero if it never
# became ready. The caller always pairs this with `subject_stop`.
subject_start() {
    local id="$1" kind rest backbone mode port log
    kind="$(subject_kind "$id")"; rest="${id#*:}"; backbone="${rest%%:*}"
    mode="$(subject_mode "$id")"; port="$(subject_port "$id")"
    log="$RESULTS_DIR/$(printf '%s' "$id" | tr ':' '-').server.log"
    case "$kind" in
        ours)
            env HTTPD_MAX_CONN=1000000 HTTPD_QUIET=1 HTTPD_PROFILE="$mode" \
                "$OURS_BIN" "$port" "$backbone" >"$log" 2>&1 & SERVER_PID=$! ;;
        nginx) nginx -c "$NGINX_CONF" -g "daemon off;" >"$log" 2>&1 & SERVER_PID=$! ;;
        caddy)
            mkdir -p "$RESULTS_DIR/caddy-home"
            env HOME="$RESULTS_DIR/caddy-home" XDG_DATA_HOME="$RESULTS_DIR/caddy-home" \
                caddy run --config "$CADDY_CONF" --adapter caddyfile >"$log" 2>&1 & SERVER_PID=$! ;;
        hummingbird) "$HB_BIN" "$port" >"$log" 2>&1 & SERVER_PID=$! ;;
        vapor) "$VAPOR_BIN" "$port" >"$log" 2>&1 & SERVER_PID=$! ;;
        go) "$GO_BIN" "$port" >"$log" 2>&1 & SERVER_PID=$! ;;
        bun) bun run "$SCRIPT_DIR/bun/server.js" "$port" >"$log" 2>&1 & SERVER_PID=$! ;;
        rust) "$RUST_BIN" "$port" >"$log" 2>&1 & SERVER_PID=$! ;;
        django-wsgi)
            env PYTHONPATH="$SCRIPT_DIR/django/djangoapp" DJANGO_SETTINGS_MODULE=benchsite.settings \
                "$VENV/bin/gunicorn" benchsite.wsgi:application --bind "127.0.0.1:$port" \
                --workers "$DJANGO_WORKERS" --log-level error >"$log" 2>&1 & SERVER_PID=$! ;;
        django-asgi)
            env PYTHONPATH="$SCRIPT_DIR/django/djangoapp" DJANGO_SETTINGS_MODULE=benchsite.settings \
                BENCH_ASYNC=1 "$VENV/bin/uvicorn" benchsite.asgi:application --host 127.0.0.1 \
                --port "$port" --workers "$DJANGO_WORKERS" --log-level error \
                >"$log" 2>&1 & SERVER_PID=$! ;;
        *) return 1 ;;
    esac
    wait_ready "http://127.0.0.1:$port/health"
}

subject_stop() { local port; port="$(subject_port "$1")"; stop_server; reap_port "$port"; sleep 0.3; }

# shuffle <seed> <items...> — a deterministic permutation, so a recorded seed reproduces the order.
shuffle() {
    local seed="$1"; shift
    printf '%s\n' "$@" | awk -v seed="$seed" 'BEGIN{srand(seed)} {print rand() "\t" $0}' \
        | sort -g | cut -f2-
}

scenario_key() { printf '%s' "${1#*:}" | tr -c 'A-Za-z0-9' '_'; }

# --- build every subject's binary --------------------------------------------------------------------
build_swift_pkg() {
    local src="$1" product="$2" work bin
    work="$SWIFT_PKG_WORK/$product"; bin="$work/.build/release/$product"
    # SwiftPM mis-resolves a package nested in another package's git tree, so the two SwiftNIO
    # packages are copied outside the repo to build. Reused until a source file is newer.
    if [ ! -x "$bin" ] || [ -n "$(find "$src" -name '*.swift' -newer "$bin" 2>/dev/null | head -1)" ]; then
        rm -rf "$work" && mkdir -p "$work" && cp -R "$src/." "$work/" && rm -rf "$work/.build"
        # Carry the repo's toolchain pin out with the sources. Without it `swiftly` finds no
        # `.swift-version` in the copied tree, selects nothing, and both SwiftNIO peers silently
        # dropped out of the field with "No installed swift toolchain is selected" — which is how a
        # comparison against "the SwiftNIO frameworks" can be reported with neither of them present.
        cp "$REPO_ROOT/.swift-version" "$work/.swift-version" 2>/dev/null || true
        ( cd "$work" && swift build -c release ) >"$RESULTS_DIR/$product.build.log" 2>&1
    fi
    [ -x "$bin" ] && printf '%s' "$bin"
}

echo "building httpd-example (release)…"
swift build -c release --package-path "$REPO_ROOT" --scratch-path "$SCRATCH" --product httpd-example \
    >"$RESULTS_DIR/_build.log" 2>&1 || { echo "error: build failed (see _build.log)" >&2; exit 1; }
OURS_BIN="$SCRATCH/release/httpd-example"

PAYLOAD="$(printf 'from-scratch swift http server. %.0s' $(seq 1 32))"   # 32 × 32 B = 1024 B
NGINX_CONF="$RESULTS_DIR/nginx.run.conf"; CADDY_CONF="$RESULTS_DIR/Caddyfile.run"
sed "s#__PAYLOAD__#$PAYLOAD#g" "$SCRIPT_DIR/servers/nginx.conf" >"$NGINX_CONF"
sed "s#__PAYLOAD__#$PAYLOAD#g" "$SCRIPT_DIR/servers/Caddyfile" >"$CADDY_CONF"
HB_BIN=""; VAPOR_BIN=""; GO_BIN=""; RUST_BIN=""; VENV="$SCRIPT_DIR/django/.venv"

# Assemble the subject list, skipping any server whose toolchain or build is absent.
SUBJECTS=()
for kind in $SERVERS; do
    case "$kind" in
        nginx|caddy|bun)
            command -v "$kind" >/dev/null || { echo "skip $kind (not installed)"; continue; } ;;
        go)
            command -v go >/dev/null || { echo "skip go (toolchain absent)"; continue; }
            GO_BIN="$RESULTS_DIR/go-bench"
            ( cd "$SCRIPT_DIR/go" && go build -o "$GO_BIN" . ) >"$RESULTS_DIR/go.build.log" 2>&1
            [ -x "$GO_BIN" ] || { echo "skip go (build failed)"; continue; } ;;
        rust)
            command -v cargo >/dev/null || { echo "skip rust (cargo absent)"; continue; }
            echo "building rust (release)…"
            ( cd "$SCRIPT_DIR/rust" && cargo build --release ) >"$RESULTS_DIR/rust.build.log" 2>&1
            RUST_BIN="$SCRIPT_DIR/rust/target/release/rust-bench"
            [ -x "$RUST_BIN" ] || { echo "skip rust (build failed)"; continue; } ;;
        hummingbird)
            echo "building hummingbird (out-of-tree)…"
            HB_BIN="$(build_swift_pkg "$SCRIPT_DIR/hummingbird" hb-bench)"
            [ -n "$HB_BIN" ] || { echo "skip hummingbird (build failed)"; continue; } ;;
        vapor)
            echo "building vapor (out-of-tree)…"
            VAPOR_BIN="$(build_swift_pkg "$SCRIPT_DIR/vapor" vapor-bench)"
            [ -n "$VAPOR_BIN" ] || { echo "skip vapor (build failed)"; continue; } ;;
        django-wsgi|django-asgi)
            [ -x "$VENV/bin/python" ] || { echo "skip $kind (no venv — see README)"; continue; } ;;
    esac
    for mode in $(subject_modes "$kind"); do
        if [ "$kind" = "ours" ]; then
            for backbone in $BACKBONES; do SUBJECTS+=("ours:$backbone:$mode"); done
        else
            SUBJECTS+=("$kind::$mode")
        fi
    done
done
[ "${#SUBJECTS[@]}" -gt 0 ] || { echo "error: no subjects to measure" >&2; exit 1; }

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo
echo "subjects=${#SUBJECTS[@]}  scenarios=[$SCENARIOS]  connections=$CONNECTIONS  duration=$DURATION"
echo "rounds=$ROUNDS  statistic=median-of-$ROUNDS  accept-encoding='$ACCEPT_ENCODING'  seed=$SEED  ncpu=$NCPU"
echo

# --- phase 1: byte equivalence, before a single timed request ----------------------------------------
echo "── parity gate: fetching every route from every subject and diffing the bytes ──"
: >"$PARITY_DIR/_parity.tsv"
for id in "${SUBJECTS[@]}"; do
    label="$(subject_label "$id"):$(subject_mode "$id")"
    if ! subject_start "$id"; then
        echo "  $label: never became ready — excluded"; subject_stop "$id"; continue
    fi
    base="http://127.0.0.1:$(subject_port "$id")"
    for scen in $SCENARIOS; do
        parity_probe "$label" "$base" "${scen%%:*}" "${scen#*:}" "$(scenario_key "$scen")" \
            "$PARITY_DIR" "$ACCEPT_ENCODING" "$ECHO_BODY"
    done
    subject_stop "$id"
done

PARITY_STATUS=pass
parity_verdict "$PARITY_DIR/_parity.tsv" >"$PARITY_DIR/_verdict.tsv" || PARITY_STATUS=fail
column -t -s"$(printf '\t')" "$PARITY_DIR/_verdict.tsv" 2>/dev/null || cat "$PARITY_DIR/_verdict.tsv"
if [ "$PARITY_STATUS" = fail ]; then
    echo
    echo "PARITY FAILED — subjects returned different bytes for the routes marked FAIL above."
    echo "A throughput comparison across servers that answer differently is not a measurement."
    if [ "$PARITY_ENFORCE" = "1" ]; then
        echo "Aborting. Set PARITY_ENFORCE=0 to record the mismatch and continue (diagnosis only)."
        exit 2
    fi
    echo "PARITY_ENFORCE=0 — continuing; every number below is NOT comparable across subjects."
fi
echo

# --- phase 2: the rounds ------------------------------------------------------------------------------
# bench_one <label> <mode> <round> <url> <method> <scenario-key>
bench_one() {
    local label="$1" mode="$2" round="$3" url="$4" method="$5" key="$6" json slug
    slug="$(printf '%s' "${label}_${mode}_${key}_r${round}" | tr -c 'A-Za-z0-9_' '_')"
    json="$RESULTS_DIR/oha__$slug.json"
    local common=(-c "$CONNECTIONS" --no-tui -H "Accept-Encoding: $ACCEPT_ENCODING")
    [ -n "$RATE" ] && common+=(-q "$RATE")
    [ "$method" = "POST" ] && common+=(-m POST -d "$ECHO_BODY" -H "Content-Type: application/json")
    [ "$WARMUP" != "0" ] && oha -z "$WARMUP" "${common[@]}" "$url" >/dev/null 2>&1
    if ! oha -z "$DURATION" "${common[@]}" --output-format json "$url" >"$json" 2>/dev/null; then
        printf '%s\t%s\t%s\t%s\t-\t0\t0\t0\t0\tfailed\n' "$round" "$label" "$mode" "$key" \
            >>"$SAMPLES_TSV"
        return
    fi
    # A cell counts only when >=99 % of responses are 2xx: oha's success rate treats a 4xx as a
    # successful exchange, so a server 404-ing a route it lacks would otherwise post real throughput.
    local total twoxx
    total=$(jq -r '[.statusCodeDistribution[]?] | add // 0' "$json")
    twoxx=$(jq -r '[.statusCodeDistribution | to_entries[]? | select(.key|startswith("2")) | .value] | add // 0' "$json")
    if [ "${total:-0}" = "0" ] || awk "BEGIN{exit !($twoxx < 0.99 * $total)}"; then
        printf '%s\t%s\t%s\t%s\t-\t0\t0\t0\t0\tna\n' "$round" "$label" "$mode" "$key" >>"$SAMPLES_TSV"
        return
    fi
    jq -r --arg r "$round" --arg l "$label" --arg m "$mode" --arg k "$key" \
        '[$r, $l, $m, $k, "-",
          (.summary.requestsPerSec // 0 | tostring),
          ((.latencyPercentiles."p50"   // 0) * 1000 | tostring),
          ((.latencyPercentiles."p99"   // 0) * 1000 | tostring),
          ((.latencyPercentiles."p99.9" // 0) * 1000 | tostring),
          "ok"] | @tsv' "$json" >>"$SAMPLES_TSV"
}

printf 'round\tsubject\tmode\tscenkey\tscenario\trps\tp50\tp99\tp999\tstatus\n' >"$SAMPLES_TSV"
: >"$ROUNDS_TSV"
for round in $(seq 1 "$ROUNDS"); do
    round_seed=$(( SEED + round ))
    ORDER=()
    while IFS= read -r line; do ORDER+=("$line"); done < <(shuffle "$round_seed" "${SUBJECTS[@]}")
    start_sample="$(host_sample start)"
    start_load="$(printf '%s' "$start_sample" | cut -f3)"
    echo "════ round $round/$ROUNDS — seed $round_seed, load1 $start_load ════"
    echo "     order: ${ORDER[*]}"
    for id in "${ORDER[@]}"; do
        label="$(subject_label "$id")"; mode="$(subject_mode "$id")"
        printf '  → %-22s [%-5s] … ' "$label" "$mode"
        if ! subject_start "$id"; then
            echo "never ready"; subject_stop "$id"; continue
        fi
        base="http://127.0.0.1:$(subject_port "$id")"
        for scen in $SCENARIOS; do
            bench_one "$label" "$mode" "$round" "$base${scen#*:}" "${scen%%:*}" "$(scenario_key "$scen")"
        done
        echo "done"
        subject_stop "$id"
    done
    end_sample="$(host_sample end)"
    end_load="$(printf '%s' "$end_sample" | cut -f3)"
    verdict="$(host_round_verdict "$start_load" "$end_load" "$LOAD_DRIFT_MAX" "$NCPU" \
        "$LOAD_CEILING_PER_CPU")"
    drift="$(host_drift_fraction "$start_load" "$end_load")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$round" "$round_seed" "$start_load" "$end_load" "$drift" "$verdict" "${ORDER[*]}" \
        >>"$ROUNDS_TSV"
    echo "  round $round: load $start_load → $end_load (drift $drift) — $verdict"
done
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- phase 3: aggregate, render, emit ------------------------------------------------------------------
# Eligible rounds: the clean ones, unless there are none — in which case every round is used and the
# whole run is stamped NOT DECISION-GRADE rather than silently reported as if it were.
CLEAN_ROUNDS="$(awk -F'\t' '$6 == "clean" {printf "%s ", $1}' "$ROUNDS_TSV")"
GRADE=decision-grade
if [ -z "$CLEAN_ROUNDS" ]; then
    CLEAN_ROUNDS="$(awk -F'\t' '{printf "%s ", $1}' "$ROUNDS_TSV")"
    GRADE="NOT-decision-grade (no clean round: every round drifted or ran on a contended host)"
elif [ "$(printf '%s' "$CLEAN_ROUNDS" | wc -w | tr -d ' ')" -lt "$ROUNDS" ]; then
    GRADE="partial ($(printf '%s' "$CLEAN_ROUNDS" | wc -w | tr -d ' ')/$ROUNDS rounds clean)"
fi
report_aggregate "$SAMPLES_TSV" "$CLEAN_ROUNDS" >"$RESULTS_DIR/_aggregate.tsv"
STATISTIC="median of $(printf '%s' "$CLEAN_ROUNDS" | wc -w | tr -d ' ') round(s)"

echo
echo "## Comparative matrix — $STATISTIC — $GRADE"
echo
for scen in $SCENARIOS; do
    report_markdown "$RESULTS_DIR/_aggregate.tsv" "$(scenario_key "$scen")" \
        "$(printf '%s %s' "${scen%%:*}" "${scen#*:}")" "$STATISTIC"
done

# The floor-vs-full price, paired within each round so common-mode drift cancels. Only meaningful
# when both profiles were measured for the same subject, i.e. MODES covered both.
report_paired "$SAMPLES_TSV" "$CLEAN_ROUNDS" >"$RESULTS_DIR/_paired.tsv"
if [ -s "$RESULTS_DIR/_paired.tsv" ]; then
    echo "### What the middleware chain costs (paired within each round)"
    echo
    echo "\`cost\` = 1 − median(full ÷ floor) over rounds that measured both, seconds apart on the"
    echo "same box. \`full slower\` is the sign count — the claim that survives a noisy host."
    echo
    echo '| subject | scenario | rounds | cost | ratio range | full slower |'
    echo '|---|---|---:|---:|---:|---:|'
    while IFS=$'\t' read -r subject key rounds med lo hi slower; do
        printf '| %s | %s | %s | %s | %s–%s | %s/%s |\n' "$subject" "$key" "$rounds" \
            "$(awk -v m="$med" 'BEGIN{printf "%.1f %%", (1 - m) * 100}')" \
            "$(awk -v v="$lo" 'BEGIN{printf "%.2f", v}')" \
            "$(awk -v v="$hi" 'BEGIN{printf "%.2f", v}')" "$slower" "$rounds"
    done <"$RESULTS_DIR/_paired.tsv"
    echo
fi

# results.json — the machine-readable record, assembled with jq so nothing hand-escapes.
jq -n \
    --arg startedAt "$STARTED_AT" --arg finishedAt "$FINISHED_AT" \
    --arg statistic "$STATISTIC" --arg grade "$GRADE" --arg parity "$PARITY_STATUS" \
    --arg encoding "$ACCEPT_ENCODING" --arg seed "$SEED" --arg eligible "$CLEAN_ROUNDS" \
    --arg duration "$DURATION" --arg warmup "$WARMUP" --arg connections "$CONNECTIONS" \
    --arg rounds "$ROUNDS" --arg ncpu "$NCPU" --arg scenarios "$SCENARIOS" \
    --arg driftMax "$LOAD_DRIFT_MAX" --arg loadCeiling "$LOAD_CEILING_PER_CPU" \
    --arg uname "$(uname -srm)" --arg model "$(sysctl -n hw.model 2>/dev/null || echo unknown)" \
    --rawfile samples "$SAMPLES_TSV" --rawfile roundsTsv "$ROUNDS_TSV" \
    --rawfile parityTsv "$PARITY_DIR/_parity.tsv" --rawfile aggregateTsv "$RESULTS_DIR/_aggregate.tsv" \
    --rawfile pairedTsv "$RESULTS_DIR/_paired.tsv" \
    '
    def rows($t; $names): $t | rtrimstr("\n") | split("\n")
        | map(select(length > 0) | split("\t"))
        | map([$names, .] | transpose | map({(.[0]): .[1]}) | add);
    {
      schema: "http-bench/2",
      startedAt: $startedAt, finishedAt: $finishedAt,
      statistic: $statistic, grade: $grade,
      config: {
        rounds: ($rounds | tonumber), connections: ($connections | tonumber),
        duration: $duration, warmup: $warmup, acceptEncoding: $encoding,
        scenarios: ($scenarios | split(" ")), seed: $seed,
        loadDriftMax: ($driftMax | tonumber), loadCeilingPerCPU: ($loadCeiling | tonumber),
        eligibleRounds: ($eligible | split(" ") | map(select(length > 0) | tonumber))
      },
      host: { uname: $uname, model: $model, ncpu: ($ncpu | tonumber) },
      parity: {
        status: $parity,
        probes: rows($parityTsv; ["scenkey","subject","status","bytes","sha256","contentType"])
      },
      rounds: rows($roundsTsv; ["round","seed","loadStart","loadEnd","drift","verdict","order"]),
      paired: rows($pairedTsv;
        ["subject","scenkey","rounds","ratioMedian","ratioMin","ratioMax","fullSlowerCount"]),
      samples: (rows($samples;
        ["round","subject","mode","scenkey","scenario","rps","p50","p99","p999","status"]) | .[1:]),
      aggregate: rows($aggregateTsv;
        ["subject","mode","scenkey","rounds","rpsMedian","rpsMin","rpsMax",
         "p50Median","p99Median","p999Median","status"])
    }' >"$RESULTS_DIR/results.json"

echo "grade:  $GRADE"
echo "parity: $PARITY_STATUS"
echo "json:   $RESULTS_DIR/results.json"
awk -F'\t' '{printf "round %s: load %s → %s (drift %s) — %s\n", $1, $3, $4, $5, $6}' "$ROUNDS_TSV"
