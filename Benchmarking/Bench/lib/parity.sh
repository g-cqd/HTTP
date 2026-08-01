#!/usr/bin/env bash
#
# lib/parity.sh — the byte-equivalence gate that runs BEFORE any timing.
#
# WHY. Every previous round of this comparison checked that a server answered 2xx and nothing else.
# It never checked that the servers answered the SAME THING. They did not:
#
#   * `GET /` returned a per-server greeting — "Hello from the Rust baseline.\n" (30 B) against
#     "Hello from the Go baseline.\n" (28 B) against our 71 B sentence. That route was reported as
#     "framework floor" throughput for the whole field.
#   * `oha` sends `accept-encoding: gzip, compress, deflate, br` unless told otherwise, so our
#     example's CompressionMiddleware gzipped bodies that every peer returned as identity — a
#     different wire payload AND a per-request compression cost no peer paid.
#
# A benchmark whose subjects return different bytes measures nothing. This gate fetches every route
# from every subject once, digests the body, and refuses to start timing when two subjects that both
# implement a route disagree.
#
# Scope of the claim: BODY bytes, plus the recorded `Content-Type`. Response headers necessarily
# differ (`Date`, `Server`, and — by design — the entire point of the `full` profile), so header
# equality is not the gate; body equality is what makes the throughput columns comparable.

# parity_probe <label> <base-url> <method> <path> <key> <outdir> <accept-encoding> <echo-body>
#
# One request. Appends "<key>\t<label>\t<status>\t<bytes>\t<digest>\t<content-type>" to
# <outdir>/_parity.tsv, where <status> is `ok` (2xx) or `unimplemented` (anything else, including a
# connection failure) — a server that does not implement a route is excluded from that route's
# comparison rather than failing it.
parity_probe() {
    local label="$1" base="$2" method="$3" path="$4" key="$5" outdir="$6" encoding="$7" body="$8"
    local slug file code type
    slug="$(printf '%s' "${label}__${key}" | tr -c 'A-Za-z0-9_' '_')"
    file="$outdir/body__$slug"
    local args=(-s -o "$file" --http1.1 --max-time 10 -H "Accept-Encoding: $encoding")
    if [ "$method" = "POST" ]; then
        args+=(-X POST -d "$body" -H "Content-Type: application/json")
    fi
    code="$(curl "${args[@]}" -w '%{http_code}' "$base$path" 2>/dev/null || echo 000)"
    type="$(curl "${args[@]}" -o /dev/null -w '%{content_type}' "$base$path" 2>/dev/null || true)"
    case "$code" in
        2*)
            printf '%s\t%s\tok\t%s\t%s\t%s\n' "$key" "$label" \
                "$(wc -c <"$file" | tr -d ' ')" \
                "$(shasum -a 256 <"$file" | awk '{print $1}')" "${type:-unknown}" ;;
        *)
            printf '%s\t%s\tunimplemented\t0\t-\t-\n' "$key" "$label" ;;
    esac >>"$outdir/_parity.tsv"
}

# parity_verdict <parity-tsv>
#
# A pure function over the probe table — no network, which is what makes it testable (selftest.sh).
# Prints "<key>\tPASS|FAIL\t<distinct-digest-count>\t<detail>" per scenario key and returns non-zero
# when any key has more than one distinct body digest among the subjects that implement it.
parity_verdict() {
    awk -F'\t' '
        $3 == "ok" {
            key = $1; digest = $5; pair = key SUBSEP digest
            if (!(key in keySeen)) { keys[++n] = key; keySeen[key] = 1 }
            if (!(pair in pairSeen)) { pairSeen[pair] = 1; distinct[key]++; bytes[pair] = $4 }
            members[pair] = members[pair] " " $2
        }
        END {
            bad = 0
            for (i = 1; i <= n; i++) {
                key = keys[i]
                if (distinct[key] <= 1) { printf "%s\tPASS\t1\t-\n", key; continue }
                bad = 1
                detail = ""
                for (pair in pairSeen) {
                    split(pair, field, SUBSEP)
                    if (field[1] != key) continue
                    detail = detail sprintf("[%s %sB ->%s] ", \
                        substr(field[2], 1, 12), bytes[pair], members[pair])
                }
                printf "%s\tFAIL\t%d\t%s\n", key, distinct[key], detail
            }
            exit bad
        }
    ' "$1"
}
