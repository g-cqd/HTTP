#!/bin/bash
#
#  soak.sh — long-duration adversarial soak against httpd-example, asserting an RSS plateau.
#
#  WHY THIS EXISTS. The conformance and benchmark gates prove the server is CORRECT and FAST for a
#  bounded run; neither proves it is STABLE for a sustained one. A connection-lifetime leak, an
#  unbounded per-request retain, or a slowloris amplification does not show up in a 5-second h2load
#  burst — it shows up as a resident-set that climbs for an hour under mixed hostile load. This script
#  drives that hour (configurable) and turns "the memory plateaus" from a claim into a pass/fail.
#
#  WHAT IT DRIVES (all generators are REQUIRED — a soak that silently skips a generator reads as
#  coverage it does not have, so a missing tool is a hard failure, never a skip):
#    • sustained closed-loop HTTP/1.1 load (oha) on two routes — the steady-state baseline
#    • sustained HTTP/2 (h2c prior-knowledge) load (oha --http2) — the multiplexed path
#    • slowloris: trickle-header connections opened and held open, one drip every few seconds, never
#      completing — the classic per-connection-state amplifier (RFC 9110 slow-read/slow-write class)
#    • connection churn: rapid connect/serve/close — exercises the accept+teardown path allocation
#    • abrupt resets: requests killed mid-flight — exercises the half-open teardown / RST path
#
#  THE PLATEAU RULE (documented here so it is not reverse-engineered from code). RSS (KB, per-process,
#  `ps -o rss=`) is sampled every SOAK_SAMPLE_INTERVAL seconds for the whole run. The series is split
#  into equal thirds by sample count:
#      third 1  = WARMUP           — discarded (steady state is not reached instantly: table growth,
#                                     connection pools, and first-touch page-ins are not a leak)
#      third 2  = MID  baseline    — median RSS here is the reference
#      third 3  = FINAL            — median RSS here is compared against the reference
#  A robust MEDIAN-of-thirds comparison is used rather than a least-squares slope: medians ignore the
#  transient spikes that a trickle/reset workload produces and need no float math in bash. The run
#  PASSES the plateau test when:
#      median(final) <= median(mid) * (1 + SOAK_REL_TOL) + SOAK_ABS_TOL_KB
#  i.e. the resident set in the final third is not meaningfully above the mid third. REL_TOL (default
#  3%) absorbs steady-state jitter; ABS_TOL_KB (default 8 MiB) is a small-number floor so a few MiB of
#  arena noise on an otherwise-flat process is not read as growth. A genuinely leaking process climbs
#  monotonically and blows past both.
#
#  OTHER VERDICT INPUTS (all must hold): the server process is still alive at the end; no crash report
#  was written during the run; and a byte-exact check of a known route still returns the right body
#  (a server that is alive but wedged is not a pass).
#
#  EXIT CODE IS THE VERDICT: 0 = plateau held + alive + correct + no crash; non-zero otherwise.
#
#  USAGE / KNOBS:
#    scripts/soak.sh                       # default 30-minute soak
#    SOAK_DURATION=120 scripts/soak.sh     # 2-minute local smoke
#  Env: SOAK_DURATION (s, default 1800), SOAK_PORT (default 18099 — a FIXED port, not 0: the example
#  prints its REQUESTED port, so an ephemeral bind would not surface the real one; a fixed port matches
#  the h2spec/h3 jobs and is probed for readiness), SOAK_HOST (default 127.0.0.1),
#  SOAK_SAMPLE_INTERVAL (s, default 5), SOAK_REL_TOL (default 0.03), SOAK_ABS_TOL_KB (default 8192),
#  SOAK_BACKBONE (default posixKqueue on Darwin / posixEpoll on Linux), SOAK_SLOWLORIS_CONNS (default
#  50), SOAK_LOAD_CONNS (default 50).
#
set -euo pipefail

# --- Configuration -----------------------------------------------------------------------------------
DURATION="${SOAK_DURATION:-1800}"
PORT="${SOAK_PORT:-18099}"
HOST="${SOAK_HOST:-127.0.0.1}"
SAMPLE_INTERVAL="${SOAK_SAMPLE_INTERVAL:-5}"
REL_TOL="${SOAK_REL_TOL:-0.03}"
ABS_TOL_KB="${SOAK_ABS_TOL_KB:-8192}"
SLOWLORIS_CONNS="${SOAK_SLOWLORIS_CONNS:-50}"
LOAD_CONNS="${SOAK_LOAD_CONNS:-50}"
if [ -z "${SOAK_BACKBONE:-}" ]; then
  case "$(uname -s)" in
    Linux) BACKBONE="posixEpoll" ;;
    *) BACKBONE="posixKqueue" ;;
  esac
else
  BACKBONE="$SOAK_BACKBONE"
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${SCRATCH:-$REPO/.build-soak}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/soak.XXXXXX")"
RSS_LOG="$WORK/rss.tsv"
BASE_URL="http://$HOST:$PORT"

# Background generator PIDs, killed on exit.
GEN_PIDS=()
SERVER_PID=""

log() { printf '==> %s\n' "$*"; }
err() { printf '!! %s\n' "$*" >&2; }

# Kill every generator and its descendants (oha, the slowloris/churn/reset subshells and their
# sleep/curl children) — but NEVER the server, which is also a child of this script. A blanket
# `pkill -P $$` would take the server down with the generators and make the final liveness check lie.
stop_generators() {
  for pid in ${GEN_PIDS[@]+"${GEN_PIDS[@]}"}; do
    pkill -P "$pid" 2>/dev/null || true   # the subshell's sleep/curl/printf children
    kill "$pid" 2>/dev/null || true       # the subshell / oha itself
  done
  GEN_PIDS=()
}
cleanup() {
  stop_generators
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# --- Preflight: every generator's tooling must exist (fail loud, never skip) -------------------------
require() {
  command -v "$1" >/dev/null 2>&1 || { err "required tool '$1' not found — a soak that skips a generator is not coverage"; exit 2; }
}
require oha
require curl
require ps
# Slowloris uses bash's /dev/tcp net-redirection; prove it is compiled in before promising the
# generator runs. Connecting to port 0 always fails, but a bash WITHOUT /dev/tcp fails with a
# filesystem error ("No such file or directory") rather than a connection error — that distinguishes
# "feature absent" from "connection refused", and only the former should abort.
devtcp_msg="$(bash -c 'exec 3<>/dev/tcp/127.0.0.1/0' 2>&1 || true)"
case "$devtcp_msg" in
  *"No such file or directory"*|*"not supported"*)
    err "this bash lacks /dev/tcp net-redirection — slowloris generator cannot run"; exit 2 ;;
esac

# --- Build + start the server ------------------------------------------------------------------------
log "building httpd-example (release)"
swift build -c release --product httpd-example --scratch-path "$SCRATCH" >/dev/null
BIN="$(swift build -c release --product httpd-example --scratch-path "$SCRATCH" --show-bin-path)/httpd-example"

log "starting server on $BASE_URL via $BACKBONE"
CRASH_SINCE="$(date +%s)"
# HTTPD_QUIET drops the per-request access log (it would dominate the process under this load and is
# not what we are measuring); HTTPD_MAX_CONN lifts the single-IP DoS guard the loopback load trips.
HTTPD_QUIET=1 HTTPD_MAX_CONN=100000 "$BIN" "$PORT" "$BACKBONE" >"$WORK/httpd.log" 2>&1 &
SERVER_PID=$!

# Wait for the listener (covers process spawn + bind).
ready=0
for _ in $(seq 1 60); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    err "server exited during startup:"; cat "$WORK/httpd.log" >&2; exit 3
  fi
  if curl -s --max-time 1 -o /dev/null "$BASE_URL/health"; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || { err "server never became ready"; cat "$WORK/httpd.log" >&2; exit 3; }
log "server ready (pid $SERVER_PID)"

DEADLINE=$(( $(date +%s) + DURATION ))

# --- Generators ---------------------------------------------------------------------------------------
# oha runs itself for the whole duration via -z; the trickle/churn/reset loops poll the deadline.

# 1 & 2: sustained closed-loop HTTP/1.1 on two routes.
oha -z "${DURATION}s" -c "$LOAD_CONNS" --no-tui \
  "$BASE_URL/plaintext" >"$WORK/oha-plaintext.txt" 2>&1 &
GEN_PIDS+=($!)
oha -z "${DURATION}s" -c "$LOAD_CONNS" --no-tui \
  "$BASE_URL/json" >"$WORK/oha-json.txt" 2>&1 &
GEN_PIDS+=($!)

# 3: sustained HTTP/2 (h2c prior knowledge — cleartext, so oha --http2 negotiates by prior knowledge).
oha -z "${DURATION}s" --http2 -c 20 --no-tui \
  "$BASE_URL/plaintext" >"$WORK/oha-h2.txt" 2>&1 &
GEN_PIDS+=($!)

# 4: slowloris — hold SLOWLORIS_CONNS connections open, each dripping one header line every few
# seconds and never sending the terminating blank line, so the connection stays in header-read state.
# One background worker per connection slot; each re-dials as soon as the server times a drip out.
slowloris_one() {
  exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || return 0
  printf 'GET / HTTP/1.1\r\nHost: %s\r\n' "$HOST" >&3 2>/dev/null || return 0
  local n=0
  while [ "$(date +%s)" -lt "$DEADLINE" ] && [ "$n" -lt 500 ]; do
    printf 'X-Drip-%d: hold\r\n' "$n" >&3 2>/dev/null || return 0
    n=$((n + 1))
    sleep 7
  done
  exec 3>&- 2>/dev/null || true
}
for _ in $(seq 1 "$SLOWLORIS_CONNS"); do
  ( while [ "$(date +%s)" -lt "$DEADLINE" ]; do slowloris_one; done ) &
  GEN_PIDS+=($!)
done

# 5: connection churn — rapid open/serve/close, one new TCP connection per request (no keepalive).
(
  while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    curl -s --max-time 2 -H 'Connection: close' -o /dev/null "$BASE_URL/plaintext" 2>/dev/null || true
  done
) &
GEN_PIDS+=($!)

# 6: abrupt resets — start a request and kill it mid-flight so the connection is torn down half-open.
(
  while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    curl -s --max-time 0.05 -o /dev/null "$BASE_URL/large" 2>/dev/null || true
    # Also a raw half-write then immediate close (RST-ish): partial request, no completion.
    ( exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null && printf 'GET /large HTTP/1.1\r\nHo' >&3 2>/dev/null; exec 3>&- 2>/dev/null ) || true
  done
) &
GEN_PIDS+=($!)

log "generators launched: oha(h1 x2), oha(h2), slowloris x$SLOWLORIS_CONNS, churn, resets"
log "driving $DURATION s of load; sampling RSS every ${SAMPLE_INTERVAL}s"

# --- Sample RSS for the whole run --------------------------------------------------------------------
: >"$RSS_LOG"
sample_count=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    err "server process died mid-soak — crash suspected"
    tail -40 "$WORK/httpd.log" >&2 || true
    break
  fi
  rss="$(ps -o rss= -p "$SERVER_PID" 2>/dev/null | tr -d ' ')"
  if [ -n "$rss" ]; then
    printf '%s\t%s\n' "$(date +%s)" "$rss" >>"$RSS_LOG"
    sample_count=$((sample_count + 1))
  fi
  sleep "$SAMPLE_INTERVAL"
done

# --- Stop generators before the final assertions -----------------------------------------------------
# Only the generators — the server stays up for the liveness + correctness probes below.
stop_generators
sleep 2  # let in-flight teardown settle before the final correctness probe

# --- Verdict inputs ----------------------------------------------------------------------------------
verdict_ok=1
reasons=()

# (a) process alive
alive=0
if kill -0 "$SERVER_PID" 2>/dev/null; then alive=1; else verdict_ok=0; reasons+=("server process is not alive"); fi

# (b) no crash report written during the run (macOS DiagnosticReports; Linux core files)
crash_found=""
if [ "$(uname -s)" = "Darwin" ]; then
  for dir in "$HOME/Library/Logs/DiagnosticReports" "/Library/Logs/DiagnosticReports"; do
    [ -d "$dir" ] || continue
    while IFS= read -r report; do
      [ -n "$report" ] || continue
      if [ "$(stat -f %m "$report" 2>/dev/null || echo 0)" -ge "$CRASH_SINCE" ]; then
        crash_found="$report"; break
      fi
    done < <(ls "$dir"/httpd-example* 2>/dev/null || true)
    [ -n "$crash_found" ] && break
  done
else
  crash_found="$(find . -maxdepth 2 -name 'core*' -newermt "@$CRASH_SINCE" 2>/dev/null | head -1 || true)"
fi
if [ -n "$crash_found" ]; then verdict_ok=0; reasons+=("crash report written during run: $crash_found"); fi

# (c) still answers correctly — byte-exact check of a known route
expected="Hello, World!"
actual="$(curl -s --max-time 5 "$BASE_URL/plaintext" 2>/dev/null || true)"
if [ "$actual" != "$expected" ]; then
  verdict_ok=0; reasons+=("final correctness check failed: /plaintext returned '$actual' (expected '$expected')")
fi

# (d) RSS plateau — median of the final third must not exceed the mid third beyond tolerance.
median() {
  # median of stdin (one integer per line). Empty input → empty output.
  sort -n | awk '{ a[NR]=$1 } END { if (NR==0) exit; if (NR%2) print a[(NR+1)/2]; else printf "%d\n", (a[NR/2]+a[NR/2+1])/2 }'
}
n="$(wc -l <"$RSS_LOG" | tr -d ' ')"
rss_start="?"; rss_mid="?"; rss_end="?"; plateau="SKIPPED"
if [ "$n" -ge 6 ]; then
  third=$((n / 3))
  mid_series="$(awk -v a=$((third + 1)) -v b=$((2 * third)) 'NR>=a && NR<=b {print $2}' "$RSS_LOG")"
  end_series="$(awk -v a=$((2 * third + 1)) 'NR>=a {print $2}' "$RSS_LOG")"
  rss_start="$(head -1 "$RSS_LOG" | awk '{print $2}')"
  rss_mid="$(printf '%s\n' "$mid_series" | median)"
  rss_end="$(printf '%s\n' "$end_series" | median)"
  # threshold = mid * (1 + REL_TOL) + ABS_TOL_KB, computed in integer awk (REL_TOL as a float is fine).
  threshold="$(awk -v m="$rss_mid" -v r="$REL_TOL" -v a="$ABS_TOL_KB" 'BEGIN { printf "%d", m*(1+r)+a }')"
  if [ "$rss_end" -le "$threshold" ]; then
    plateau="PASS"
  else
    plateau="FAIL"; verdict_ok=0
    reasons+=("RSS plateau breached: final median ${rss_end}KB > threshold ${threshold}KB (mid ${rss_mid}KB +${REL_TOL}rel +${ABS_TOL_KB}KB)")
  fi
else
  plateau="INSUFFICIENT_SAMPLES"; verdict_ok=0
  reasons+=("only $n RSS samples — need >=6 for a thirds comparison; raise SOAK_DURATION or lower SOAK_SAMPLE_INTERVAL")
fi

# --- Requests driven (sum oha [200] counts across the three load generators) --------------------------
sum_responses() {
  local total=0 f c
  for f in "$WORK"/oha-plaintext.txt "$WORK"/oha-json.txt "$WORK"/oha-h2.txt; do
    [ -f "$f" ] || continue
    c="$(grep -oE '\[2[0-9][0-9]\] [0-9]+ responses' "$f" | grep -oE '[0-9]+ responses' | grep -oE '[0-9]+' | awk '{s+=$1} END {print s+0}')"
    total=$((total + ${c:-0}))
  done
  echo "$total"
}
requests_driven="$(sum_responses)"

# --- Summary table -----------------------------------------------------------------------------------
kib() { awk -v k="$1" 'BEGIN { if (k ~ /^[0-9]+$/) printf "%.1f MiB", k/1024; else printf "%s", k }'; }
verdict_text="PASS"; [ "$verdict_ok" = 1 ] || verdict_text="FAIL"

printf '\n'
printf '========================= SOAK SUMMARY =========================\n'
printf '  %-22s %s\n' "duration"        "${DURATION}s"
printf '  %-22s %s\n' "backbone"        "$BACKBONE"
printf '  %-22s %s\n' "requests driven" "$requests_driven (oha [2xx] across h1x2 + h2)"
printf '  %-22s %s\n' "RSS samples"     "$n (every ${SAMPLE_INTERVAL}s)"
printf '  %-22s %s\n' "RSS start"       "$(kib "$rss_start")"
printf '  %-22s %s\n' "RSS mid (median)" "$(kib "$rss_mid")"
printf '  %-22s %s\n' "RSS end (median)" "$(kib "$rss_end")"
printf '  %-22s %s\n' "plateau"         "$plateau (rel<=${REL_TOL}, abs<=${ABS_TOL_KB}KB)"
printf '  %-22s %s\n' "server alive"    "$([ "$alive" = 1 ] && echo yes || echo NO)"
printf '  %-22s %s\n' "crash report"    "$([ -z "$crash_found" ] && echo none || echo "$crash_found")"
printf '  %-22s %s\n' "final /plaintext" "$([ "$actual" = "$expected" ] && echo correct || echo WRONG)"
printf '  %-22s %s\n' "VERDICT"         "$verdict_text"
printf '================================================================\n'
if [ "$verdict_ok" != 1 ]; then
  printf '\nFailure reasons:\n'
  for r in "${reasons[@]}"; do printf '  - %s\n' "$r"; done
fi

# Emit to the GitHub step summary when running in CI.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Soak summary (${DURATION}s, $BACKBONE)"
    echo ""
    echo "| metric | value |"
    echo "| --- | --- |"
    echo "| requests driven | $requests_driven |"
    echo "| RSS samples | $n |"
    echo "| RSS start | $(kib "$rss_start") |"
    echo "| RSS mid (median) | $(kib "$rss_mid") |"
    echo "| RSS end (median) | $(kib "$rss_end") |"
    echo "| plateau | $plateau |"
    echo "| server alive | $([ "$alive" = 1 ] && echo yes || echo NO) |"
    echo "| crash report | $([ -z "$crash_found" ] && echo none || echo "$crash_found") |"
    echo "| **verdict** | **$verdict_text** |"
  } >>"$GITHUB_STEP_SUMMARY"
fi

rm -rf "$WORK"
[ "$verdict_ok" = 1 ]
