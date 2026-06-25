#!/usr/bin/env bash
#
# fetch.sh — (re)download the vendored RFC corpus into this directory.
#
# Authoritative ASCII text from the RFC Editor. Run from anywhere; writes next to this script.
# Usage: Standards/fetch.sh        # download/refresh all
#        Standards/fetch.sh --check # verify every listed RFC is present and non-trivially sized
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# Implemented protocols + directly-related extensions. Superseded predecessors are intentionally omitted
# (they are linked from README.md, not vendored).
rfcs=(
  9110 9111 9112 9113 9114   # HTTP semantics / caching / 1.1 / 2 / 3
  7541 9204                  # HPACK / QPACK
  9000 9001 9002             # QUIC transport / TLS / recovery
  6455 8441 9220 7692        # WebSocket + bootstrapping (h2, h3) + permessage-deflate
  1950 1951 1952             # zlib / deflate / gzip
  6265                       # cookies
  7301 8446                  # ALPN / TLS 1.3
  7838 9218                  # Alt-Svc / priorities
  3629 5234                  # UTF-8 / ABNF
)

if [[ "${1:-}" == "--check" ]]; then
  status=0
  for n in "${rfcs[@]}"; do
    if [[ ! -s "rfc$n.txt" ]] || [[ "$(wc -c < "rfc$n.txt")" -lt 4096 ]]; then
      echo "MISSING or too small: rfc$n.txt" >&2
      status=1
    fi
  done
  [[ $status -eq 0 ]] && echo "OK: ${#rfcs[@]} RFCs present."
  exit $status
fi

for n in "${rfcs[@]}"; do
  code="$(curl -sSL -o "rfc$n.txt" -w '%{http_code}' "https://www.rfc-editor.org/rfc/rfc$n.txt")"
  printf 'rfc%-5s HTTP %s  %8s bytes\n' "$n" "$code" "$(wc -c < "rfc$n.txt" | tr -d ' ')"
  [[ "$code" == "200" ]] || { echo "FAILED rfc$n (HTTP $code)" >&2; exit 1; }
done
echo "Done: ${#rfcs[@]} RFCs."
