#!/usr/bin/env bash
#
# lib/report.sh — aggregation and rendering.
#
# ONE STATISTIC, STATED UP FRONT: the reported number is the MEDIAN of the eligible rounds. Not
# best-of-N. The previous harness reported best-of-N per cell, justified as cancelling the thermal
# bias of a fixed server order; that justification is gone because the order is now rotated, and
# best-of-N is a biased estimator of what a server does — it reports the luckiest round, which is not
# a thing any user experiences and which cannot be compared against a median taken elsewhere. Two of
# the three previous rounds of this comparison silently used different statistics (best-of-1 in the
# committed RESULTS.md, hand-recomputed medians in the two reviews), which is on its own enough to
# explain a double-digit percentage difference between them.
#
# Min and max across rounds are reported beside every median, so a cell whose rounds disagree cannot
# hide inside its own average. A cell whose max/min spread exceeds 1.5x is flagged: the routed cell in
# the 2026-07-31 round-1 data swung 23,848 -> 50,383 -> 30,838 RPS across three repeats of the SAME
# configuration, and its median alone tells you none of that.

# stat_median <numbers...> — median of the arguments (mean of the two middles when even).
stat_median() {
    printf '%s\n' "$@" | sort -g | awk '
        { v[NR] = $1 }
        END {
            if (NR == 0) { print "0"; exit }
            if (NR % 2) { printf "%.3f", v[(NR + 1) / 2] }
            else { printf "%.3f", (v[NR / 2] + v[NR / 2 + 1]) / 2 }
        }
    '
}

# report_aggregate <samples-tsv> <eligible-rounds-space-separated>
#
# samples-tsv columns: round, subject, mode, scenkey, scenario, rps, p50, p99, p999, status
# Emits:  subject, mode, scenkey, rounds, rps_med, rps_min, rps_max, p50_med, p99_med, p999_med, status
#
# A cell is `na` when no eligible round measured it as ok (the server does not implement the route).
report_aggregate() {
    awk -F'\t' -v eligible=" $2 " '
        function median(arr, n,   i, j, tmp) {
            for (i = 2; i <= n; i++) {      # insertion sort: one-true-awk has no asort
                tmp = arr[i]
                for (j = i - 1; j >= 1 && arr[j] > tmp; j--) arr[j + 1] = arr[j]
                arr[j + 1] = tmp
            }
            if (n == 0) return 0
            return (n % 2) ? arr[(n + 1) / 2] : (arr[n / 2] + arr[n / 2 + 1]) / 2
        }
        NR == 1 && $1 == "round" { next }                       # header
        eligible !~ (" " $1 " ") { next }                       # round excluded by the drift gate
        {
            cell = $2 SUBSEP $3 SUBSEP $4
            if (!(cell in seen)) { cells[++n] = cell; seen[cell] = 1 }
            if ($10 != "ok") { na[cell]++; next }
            k = ++count[cell]
            rps[cell, k] = $6 + 0; p50[cell, k] = $7 + 0
            p99[cell, k] = $8 + 0; p999[cell, k] = $9 + 0
        }
        END {
            for (i = 1; i <= n; i++) {
                cell = cells[i]; split(cell, f, SUBSEP)
                c = count[cell] + 0
                if (c == 0) { printf "%s\t%s\t%s\t0\t-\t-\t-\t-\t-\t-\tna\n", f[1], f[2], f[3]; continue }
                lo = rps[cell, 1]; hi = rps[cell, 1]
                for (k = 1; k <= c; k++) {
                    a[k] = rps[cell, k]; b[k] = p50[cell, k]
                    d[k] = p99[cell, k]; e[k] = p999[cell, k]
                    if (a[k] < lo) lo = a[k]
                    if (a[k] > hi) hi = a[k]
                }
                printf "%s\t%s\t%s\t%d\t%.0f\t%.0f\t%.0f\t%.3f\t%.3f\t%.3f\tok\n", \
                    f[1], f[2], f[3], c, median(a, c), lo, hi, \
                    median(b, c), median(d, c), median(e, c)
            }
        }
    ' "$1"
}

# report_paired <samples-tsv> <eligible-rounds-space-separated>
#
# The floor-vs-full price, computed as a PAIRED statistic: within a round the two profiles are
# measured seconds apart on the same box, so the per-round ratio full/floor cancels the common-mode
# drift that swamps a comparison of two independent medians. The ratio of medians is the wrong
# estimator here and can be wildly wrong — on a contended host it put `/json` at 0.66 where the
# paired median put it at 0.86.
#
# Also emits a SIGN COUNT: how many rounds had full slower than floor. That is the one claim that
# survives a noisy box, because it needs no magnitude — under a null of "no difference" it is a coin
# flip, so 42 of 55 is evidence of direction even when every individual ratio is unusable.
#
# Emits: subject, scenkey, n, ratioMedian, ratioMin, ratioMax, fullSlowerCount
report_paired() {
    awk -F'\t' -v eligible=" $2 " '
        function median(arr, n,   i, j, tmp) {
            for (i = 2; i <= n; i++) {
                tmp = arr[i]
                for (j = i - 1; j >= 1 && arr[j] > tmp; j--) arr[j + 1] = arr[j]
                arr[j + 1] = tmp
            }
            if (n == 0) return 0
            return (n % 2) ? arr[(n + 1) / 2] : (arr[n / 2] + arr[n / 2 + 1]) / 2
        }
        NR == 1 && $1 == "round" { next }
        eligible !~ (" " $1 " ") || $10 != "ok" { next }
        { rps[$2 SUBSEP $4 SUBSEP $1 SUBSEP $3] = $6 + 0
          if (!(($2 SUBSEP $4) in seen)) { cells[++n] = $2 SUBSEP $4; seen[$2 SUBSEP $4] = 1 }
          if (!($1 in roundSeen)) { rounds[++rn] = $1; roundSeen[$1] = 1 } }
        END {
            for (i = 1; i <= n; i++) {
                split(cells[i], f, SUBSEP)
                count = 0; slower = 0
                for (r = 1; r <= rn; r++) {
                    lo = rps[f[1] SUBSEP f[2] SUBSEP rounds[r] SUBSEP "floor"]
                    hi = rps[f[1] SUBSEP f[2] SUBSEP rounds[r] SUBSEP "full"]
                    if (lo <= 0 || hi <= 0) continue
                    ratio[++count] = hi / lo
                    if (hi < lo) slower++
                }
                if (count == 0) continue
                lowest = ratio[1]; highest = ratio[1]
                for (k = 1; k <= count; k++) {
                    if (ratio[k] < lowest) lowest = ratio[k]
                    if (ratio[k] > highest) highest = ratio[k]
                }
                printf "%s\t%s\t%d\t%.4f\t%.4f\t%.4f\t%d\n", \
                    f[1], f[2], count, median(ratio, count), lowest, highest, slower
            }
        }
    ' "$1"
}

# report_spread_max <aggregate-tsv> -> the widest max/min RPS spread across all measured cells,
# or "-" when nothing was measured.
#
# This is the COUNTER-SIGNAL printed beside the run grade. The 2026-08-02 runs graded every round
# not-clean while every cell's spread sat at 1.01–1.03 — five repeats agreeing to a percent is
# evidence about the run worth recording next to the verdict. It must never OVERRIDE the verdict:
# a box that is uniformly slow for the whole run (steady external load) produces a tight spread
# around numbers that are all equally wrong.
report_spread_max() {
    awk -F'\t' '
        $11 == "ok" && $6 + 0 > 0 {
            s = $7 / $6
            if (s > best) { best = s; found = 1 }
        }
        END { if (found) printf "%.2f", best; else printf "-" }
    ' "$1"
}

# report_markdown <aggregate-tsv> <scenario-key> <scenario-label> <statistic-label>
#
# One table per scenario, sorted by median RPS. The `spread` column is max/min across rounds — the
# column that says whether the median in front of it means anything.
report_markdown() {
    local agg="$1" key="$2" label="$3" statistic="$4"
    printf '### %s\n\n' "$label"
    printf 'Statistic: **%s**. `spread` = max/min RPS across rounds (>1.50 flagged).\n\n' "$statistic"
    printf '| server | profile | rps | spread | p50 (ms) | p99 (ms) | p99.9 (ms) |\n'
    printf '|---|---|---:|---:|---:|---:|---:|\n'
    awk -F'\t' -v k="$key" '$3 == k' "$agg" \
        | sort -t"$(printf '\t')" -k5 -gr \
        | while IFS=$'\t' read -r subject mode _ _ rps lo hi p50 p99 p999 status; do
            if [ "$status" != "ok" ]; then
                printf '| %s | %s | N/A | - | - | - | - |\n' "$subject" "$mode"
                continue
            fi
            local spread flag
            spread=$(awk -v a="$lo" -v b="$hi" 'BEGIN{ printf "%.2f", (a > 0 ? b / a : 0) }')
            flag=$(awk -v s="$spread" 'BEGIN{ print (s > 1.50 ? " ⚠" : "") }')
            printf '| %s | %s | %s | %s%s | %s | %s | %s |\n' \
                "$subject" "$mode" "$rps" "$spread" "$flag" "$p50" "$p99" "$p999"
        done
    printf '\n'
}
