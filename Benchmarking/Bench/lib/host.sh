#!/usr/bin/env bash
#
# lib/host.sh — host-state capture and the external-contention gate.
#
# WHY. Round 1 and round 2 of the comparative battletest were taken on the same machine at load
# averages 5.31 and 16.77 respectively, and nobody recorded that until afterwards, so the ~10 %
# swing between the rounds could not be attributed. Absolute throughput on a colocated loopback
# benchmark is a function of how much else the box is doing; a number without the host state beside
# it is not evidence. This library records the state at the START and the END of every round into
# the results file, and marks a round the box cannot vouch for.
#
# WHAT THE GATE GRADES, AND WHY IT CHANGED. The first version graded the TOTAL one-minute load
# average against LOAD_CEILING_PER_CPU. That total includes the benchmark's own workload — `oha`
# at 64 connections plus the server under test saturate cores BY DESIGN — so `clean` was
# structurally unreachable: on an idle 10-core box a single-subject run read load 1.54 → 10.63,
# every round graded `contended`, and the load fell back to 2.73 within 90 s of the run ending.
# A gate that fires on its own workload cannot distinguish a quiet host from the poisoned runs it
# was built to reject (load 16–30 from ~30 concurrent agent worktrees). The gate now grades
# EXTERNAL load only, from two signals:
#
#   * a BASELINE load average, sampled before the harness builds or starts anything — at that
#     moment every runnable thread is someone else's, so a box already past the ceiling rejects
#     every round no matter how quiet `ps` looks later;
#   * per-round EXTERNAL CPU: the summed `ps` %cpu of every process OUTSIDE the harness's own
#     process tree, normalised per CPU. The tree walk is what "subtract our own workload" means
#     concretely. kernel_task (pid 0) is also excluded: its time is dominated by servicing
#     whatever workload is running, i.e. it tracks our own load, not someone else's.
#
# The ceiling was NOT raised. Raising it would have re-admitted the load-16 runs; changing the
# signal keeps them out (via the baseline) while letting a genuinely idle box grade clean.
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

# host_external_cpu_from_table <root-pid> <ncpu>
#
# stdin: one process per line, "<pid> <ppid> <pcpu>" (the shape of `ps -axo pid=,ppid=,pcpu=`).
# Sums %cpu over every process that is neither <root-pid> nor a descendant of it, excluding pid 0,
# and prints the sum as a busy-per-CPU fraction ("903.5 % over 10 cores" -> "0.9035"). Pure over
# its input so the tree exclusion is testable without a live process table.
host_external_cpu_from_table() {
    awk -v root="$1" -v n="$2" '
        { pid[NR] = $1; parent[$1] = $2; cpu[NR] = $3 }
        END {
            for (i = 1; i <= NR; i++) {
                p = pid[i]
                if (p == 0) continue                # kernel_task services OUR load; see header
                mine = 0
                for (d = 0; d < 64; d++) {          # bounded walk: a ppid cycle cannot hang us
                    if (p == root) { mine = 1; break }
                    if (!(p in parent) || parent[p] == p) break
                    p = parent[p]
                }
                if (!mine) total += cpu[i]
            }
            if (n < 1) n = 1
            printf "%.4f", total / (100 * n)
        }'
}

# host_external_cpu [root-pid] — the live external busy-per-CPU fraction, defaulting to the
# caller's own process as the tree root. `ps` %cpu is a decaying recent average per process, so a
# burst that started seconds ago is understated; that is the best an unprivileged sample can do,
# and the baseline check above it does not share the weakness.
host_external_cpu() {
    ps -axo pid=,ppid=,pcpu= 2>/dev/null | host_external_cpu_from_table "${1:-$$}" "$(host_ncpu)"
}

# host_ext_drift <a> <b> -> |b − a|, the absolute movement of the external busy fraction across a
# round. Absolute, not relative: these are already per-CPU fractions, and a relative measure would
# reject an idle box for moving 0.01 → 0.04.
host_ext_drift() {
    awk -v a="$1" -v b="$2" 'BEGIN{ d = b - a; if (d < 0) d = -d; printf "%.4f", d }'
}

# host_round_verdict <baseline-load1> <ext-start> <ext-end> <drift-max> <ncpu> <ceiling>
#   -> "clean" | "drifted" | "contended" | "drifted+contended"
#
# `contended` means someone ELSE had the box: the pre-run baseline load per CPU exceeded the
# ceiling, or the external busy fraction did at either end of the round. `drifted` means the
# external demand MOVED underneath the round, so the servers measured early and late were not
# measured on the same machine. The harness's own load never appears in either predicate.
host_round_verdict() {
    local baseline="$1" ext_start="$2" ext_end="$3" drift_max="$4" ncpu="$5" ceiling="$6" verdict=""
    awk -v a="$ext_start" -v b="$ext_end" -v m="$drift_max" \
        'BEGIN{ d = b - a; if (d < 0) d = -d; exit !(d > m) }' \
        && verdict="drifted"
    awk -v base="$baseline" -v a="$ext_start" -v b="$ext_end" -v n="$ncpu" -v c="$ceiling" \
        'BEGIN{ n = (n < 1 ? 1 : n); exit !((base / n) > c || a > c || b > c) }' \
        && verdict="${verdict:+$verdict+}contended"
    printf '%s' "${verdict:-clean}"
}
