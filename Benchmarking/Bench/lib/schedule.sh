#!/usr/bin/env bash
#
# lib/schedule.sh — the unit of the per-round shuffle.
#
# WHY. The floor-vs-full price is a PAIRED statistic (lib/report.sh), and a pair is only worth
# pairing when its two cells were measured on the same machine. The shuffle used to permute every
# subject independently, so our floor and full cells for one backbone could land at opposite ends
# of a round — minutes apart on a box whose load the round itself was moving. In the 2026-08-02
# full-field run they sat 4–8 order slots apart in every round, and the paired estimator read the
# middleware chain as faster than its own floor. The shuffle therefore permutes UNITS: the floor
# and full cells of one backbone travel as one unit and run back-to-back, which keeps the order
# rotation across the field while bounding the pair's separation to one slot.
#
# The inner order of a pair ALTERNATES by round parity. Even back-to-back there is a residual
# one-slot drift, and a fixed inner order would hand it to the same profile every round; the
# alternation cancels it over rounds instead.

# schedule_units — stdin: subject ids, one per line ("ours:<backbone>:<mode>" or "<kind>::<mode>").
# stdout: shuffle units, preserving input order. An ours backbone measured in BOTH profiles folds
# into one "ours:<backbone>:floor+full" unit (emitted at the floor id's place); everything else is
# a unit of one.
schedule_units() {
    awk -F: '
        { ids[NR] = $0 }
        $1 == "ours" { seen[$1 ":" $2 ":" $3] = 1 }
        END {
            for (i = 1; i <= NR; i++) {
                split(ids[i], f, ":")
                if (f[1] == "ours" \
                    && seen["ours:" f[2] ":floor"] && seen["ours:" f[2] ":full"]) {
                    if (f[3] == "floor") print "ours:" f[2] ":floor+full"
                    # the full id is folded into the pair unit emitted above
                } else print ids[i]
            }
        }'
}

# schedule_expand <round> <unit> — the subject ids of one unit, one per line, in the order they
# run. Odd rounds run floor first, even rounds full first.
schedule_expand() {
    local round="$1" unit="$2" base
    case "$unit" in
        *:floor+full)
            base="${unit%:floor+full}"
            if [ $((round % 2)) -eq 1 ]; then
                printf '%s:floor\n%s:full\n' "$base" "$base"
            else
                printf '%s:full\n%s:floor\n' "$base" "$base"
            fi ;;
        *) printf '%s\n' "$unit" ;;
    esac
}
