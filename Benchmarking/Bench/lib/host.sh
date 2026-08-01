#!/usr/bin/env bash
#
# lib/host.sh — host-state capture and the load-drift gate.
#
# WHY. Round 1 and round 2 of the comparative battletest were taken on the same machine at load
# averages 5.31 and 16.77 respectively, and nobody recorded that until afterwards, so the ~10 %
# swing between the rounds could not be attributed. Absolute throughput on a colocated loopback
# benchmark is a function of how much else the box is doing; a number without the host state beside
# it is not evidence. This library records the state at the START and the END of every round into
# the results file, and marks a round whose load moved more than a stated fraction.
#
# Nothing here refuses to run. It refuses to be SILENT: a drifted or contended round is still
# recorded, still visible in the JSON, and excluded from the headline aggregate when a clean round
# exists to replace it (see lib/report.sh).

# One-minute load average as a bare number ("{ 7.98 9.70 14.43 }" -> "7.98").
host_load1() {
    sysctl -n vm.loadavg 2>/dev/null | awk '{gsub(/[{}]/,""); print ($1==""?"0":$1)}'
}

host_ncpu() { sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0; }

# Thermal pressure, best effort. There is no unprivileged thermal sysctl on Apple silicon; `pmset -g
# therm` reports the recorded warning levels and is the only reachable signal, so it is recorded
# verbatim rather than interpreted.
host_thermal() {
    local raw
    raw="$(pmset -g therm 2>/dev/null | tr '\n' ';' | sed 's/;$//')"
    printf '%s' "${raw:-unavailable}"
}

# host_sample <phase> -> "<epoch>\t<phase>\t<load1>\t<thermal>"
host_sample() { printf '%s\t%s\t%s\t%s' "$(date +%s)" "$1" "$(host_load1)" "$(host_thermal)"; }

# host_drift_fraction <load-start> <load-end> -> |end-start| / max(start, 1.0)
#
# Normalised against a floor of 1.0 rather than against `start` itself: on a genuinely idle box a
# move from 0.05 to 0.30 is a 500 % relative change but is thermally and schedulingly irrelevant,
# and gating on it would reject every good round.
host_drift_fraction() {
    awk -v a="$1" -v b="$2" 'BEGIN{ d=b-a; if (d<0) d=-d; base=(a<1.0?1.0:a); printf "%.4f", d/base }'
}

# host_round_verdict <load-start> <load-end> <drift-max> <ncpu> <load-ceiling-per-cpu>
#   -> "clean" | "drifted" | "contended" | "drifted+contended"
#
# `contended` means the box was already busy (load per CPU above the ceiling) for the WHOLE round, so
# the absolute numbers are depressed even though nothing moved. `drifted` means the box changed
# underneath the round, so the servers measured early and late were not measured on the same machine.
host_round_verdict() {
    local start="$1" end="$2" drift_max="$3" ncpu="$4" ceiling="$5" verdict=""
    awk -v d="$(host_drift_fraction "$start" "$end")" -v m="$drift_max" 'BEGIN{exit !(d>m)}' \
        && verdict="drifted"
    awk -v a="$start" -v b="$end" -v n="$ncpu" -v c="$ceiling" \
        'BEGIN{ n=(n<1?1:n); exit !((a/n)>c || (b/n)>c) }' \
        && verdict="${verdict:+$verdict+}contended"
    printf '%s' "${verdict:-clean}"
}
