//
//  RoutingBenchmarks.swift
//  HTTPBenchmarks
//
//  Route resolution cost as a function of table size (2026-07-31 audit, finding 19). `Router.resolve`
//  splits the path and linearly scans every route of the matching method, so the claimed complexity is
//  O(routes × segments) per match with allocations scaling by capture count.
//
//  These exist to decide ONE question, and the decision rule is recorded here BEFORE the numbers so it
//  cannot be retrofitted to whatever they turn out to be:
//
//      Build a compiled radix trie ONLY IF `routing/miss/1000` exceeds ~2 µs, OR `routing/match/100`
//      exceeds ~5 % of the measured end-to-end per-request CPU from the `http1/*` benchmarks.
//      Otherwise the linear scan stays and this file records why.
//
//  The rationale for setting the bar there: the audit's own recommendation is to fix the *repeated*
//  matching first (one request matched the table 2–4 times) and only then consider a different data
//  structure. A trie is a permanent increase in construction cost, memory, and the amount of code a
//  reader must hold in their head to reason about routing; it earns that only if a single match is
//  actually a visible share of serving a request.
//
//  ── MEASURED, 2026-07-31, Apple silicon, release build, p50 wall clock ────────────────────────────
//
//      routing/match/{10,100,1000}     1.50 / 1.54 / 1.54 µs      14 K instructions,  3 mallocs
//      routing/tail/{10,100,1000}      1.67 / 2.88 / 15.0 µs   16/39/259 K instructions,  3 mallocs
//      routing/miss/{1000}                          11.0 µs     208 K instructions,  3 mallocs
//      routing/capture/{static,parameters,catchAll}
//                                      1.38 / 1.92 / 2.54 µs   12/21/30 K instructions, 2/5/8 mallocs
//      (for scale) http1/RequestParser/realistic     2.71 µs;  ResponseSerializer/serialize  2.38 µs
//
//  Reading these honestly separates two costs the rule above conflates:
//
//  1. FIXED cost per `resolve` ≈ 1.4 µs / 3 mallocs, flat in table size. It is the path `split` array
//     and the parameter set, not the scan. This is ~28 % of parse-plus-serialize, which is a lot — but
//     a trie does not remove it, because a trie still splits the path and still captures parameters.
//     What removes it is matching ONCE per request instead of 2–4 times (audit findings 12 + 19), which
//     is worth ~3–4 µs per request on the h2/h3 paths and needs no new data structure.
//
//  2. SCAN cost, invisible at 10 routes, ~1.5 µs at 100, and dominant at 1000 (miss 11 µs, tail 15 µs).
//     Only this is what a trie fixes.
//
//  VERDICT: the stated rule fires on `routing/miss/1000`, so a trie is warranted **for large tables** —
//  but it is deliberately NOT built yet, because building it now would optimize the smaller term first
//  and then have to be re-measured anyway. The dispatch-plan change lands first; these benchmarks are
//  then re-run, and the trie decision is made against `routing/miss/1000` alone (the fixed cost having
//  been amortized by then). That ordering is the audit's own recommendation, and the numbers above are
//  why it is the right one rather than merely the cautious one.
//
//  Note also what the numbers rule OUT: `mallocCountTotal` is flat at 3 across every table size and
//  across hit/miss, so the "allocations scale with route count" half of the finding does not reproduce.
//  A proposed micro-optimization to allocate `Route.match`'s capture dictionary lazily would save
//  nothing — Swift's empty `Dictionary` already uses a shared singleton and does not allocate.
//
//  Table shape is deliberately adversarial-ish but realistic: one third static, one third one-parameter,
//  one third two-level-parameter, matched round-robin so branch prediction cannot memorize a single
//  path. Three lookups are measured because they have genuinely different costs:
//    • `match/N`  — an average hit (the middle of the table)
//    • `tail/N`   — the worst hit (the last route scanned)
//    • `miss/N`   — the true worst case: every route is compared and none matches
//

import Benchmark
import HTTPCore
import HTTPServer

func registerRoutingBenchmarks() {
    for size in [10, 100, 1_000] {
        let router = makeRouter(routeCount: size)
        let hitPaths = (0 ..< 16).map { samplePath(index: $0 * max(1, size / 16) % size) }
        let tailPath = samplePath(index: size - 1)

        Benchmark("routing/match/\(size)") { benchmark in
            var cursor = 0
            for _ in benchmark.scaledIterations {
                blackHole(router.match(method: .get, path: hitPaths[cursor % hitPaths.count]))
                cursor += 1
            }
        }

        Benchmark("routing/tail/\(size)") { benchmark in
            for _ in benchmark.scaledIterations {
                blackHole(router.match(method: .get, path: tailPath))
            }
        }

        Benchmark("routing/miss/\(size)") { benchmark in
            for _ in benchmark.scaledIterations {
                blackHole(router.match(method: .get, path: "/nothing/matches/this/path"))
            }
        }
    }

    // Isolates the per-match capture cost: a purely static route should not allocate at all, so a
    // non-zero `mallocCountTotal` delta against `routing/capture/static` is the parameter tax.
    let staticRouter = Router { Route.get("/health/live") { _, _, _ in .text("ok") } }
    Benchmark("routing/capture/static") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(staticRouter.match(method: .get, path: "/health/live"))
        }
    }

    let parameterRouter = Router { Route.get("/users/:id/posts/:post") { _, _, _ in .text("ok") } }
    Benchmark("routing/capture/parameters") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(parameterRouter.match(method: .get, path: "/users/42/posts/7"))
        }
    }

    let catchAllRouter = Router { Route.get("/assets/*rest") { _, _, _ in .text("ok") } }
    Benchmark("routing/capture/catchAll") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(catchAllRouter.match(method: .get, path: "/assets/css/site/main.css"))
        }
    }
}

/// A table of `routeCount` routes: one third static, one third one-parameter, one third two-level.
private func makeRouter(routeCount: Int) -> Router {
    Router {
        for index in 0 ..< routeCount {
            Route.get(patternForRoute(index: index)) { _, _, _ in .text("ok") }
        }
    }
}

private func patternForRoute(index: Int) -> String {
    switch index % 3 {
        case 0:
            "/static/\(index)/leaf"
        case 1:
            "/one/\(index)/:id"
        default:
            "/two/\(index)/:id/nested/:child"
    }
}

/// A request path that matches the route at `index`.
private func samplePath(index: Int) -> String {
    switch index % 3 {
        case 0:
            "/static/\(index)/leaf"
        case 1:
            "/one/\(index)/42"
        default:
            "/two/\(index)/42/nested/7"
    }
}
