#!/usr/bin/env bash
#
# scripts/ci-gates.sh — the package's own graph and source gates, which formatting and the analyzers cannot express.
# CI runs it after the macOS debug tests (`.ci/action.json`, command `graph-gates`); run it locally from anywhere.
#
#   • no SwiftNIO anywhere in the dependency graph (CLAUDE.md)
#   • the shared Aemi dependency contract (scripts/dependency-pinning.py, and its own tests)
#   • the request path is trap-free: one bad request must not crash the server
#   • every wire parser and decoder cites the standard it implements
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "==> no SwiftNIO in the dependency graph"
deps="$(swift package show-dependencies --format flatlist 2>/dev/null || true)"
if printf '%s\n' "$deps" | grep -iE 'swift-nio|/nio'; then
    echo "::error::SwiftNIO present in the dependency graph — forbidden by CLAUDE.md"
    exit 1
fi

echo "==> the shared Aemi dependency contract"
python3 -m unittest discover -s scripts -p 'test_dependency_pinning.py'
python3 scripts/dependency-pinning.py

echo "==> the request path is trap-free"
targets=(Sources/Core/HTTPCore Sources/Protocols/HTTP1 Sources/Protocols/HTTP2 Sources/Protocols/HPACK Sources/Protocols/QPACK
    Sources/Protocols/HTTP3 Sources/Protocols/WebSocket Sources/Server/HTTPServer Sources/Transport/HTTPTransport
    Sources/Core/HTTPConcurrency)
pattern='(fatalError|preconditionFailure|assertionFailure)\(|(^|[^A-Za-z.])precondition\(|(^|[^A-Za-z])assert\(|\.unsafelyUnwrapped'
hits="$(grep -rnE "$pattern" "${targets[@]}" --include='*.swift' 2>/dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)"
if [ -n "$hits" ]; then
    echo "$hits"
    echo "::error::process-aborting trap in the request path — one bad request must not crash the server"
    exit 1
fi

echo "==> every wire parser/decoder cites its standard"
missing=""
while IFS= read -r f; do
    grep -qE 'RFC[[:space:]]*[0-9]|§|CVE-|ISO[[:space:]/]' "$f" || missing+="$f"$'\n'
done < <(find Sources/Protocols Sources/Core/HTTPCore \( -name '*Parser.swift' -o -name '*Decoder.swift' \) | sort)
if [ -n "$missing" ]; then
    printf '%s\n' "$missing"
    echo "::error::a wire parser/decoder cites no RFC/§/CVE/ISO standard — reference the norm it implements"
    exit 1
fi
echo "graph and source gates passed"
