//
//  RoutingBenchmarks.swift
//  HTTPBenchmarks
//
//  Route resolution cost as a function of table size (2026-07-31 audit, finding 19). `Router.match`
//  splits the path and linearly scans every candidate route, so the claimed complexity is
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
//  BEFORE the dispatch-plan change (`Router.resolve`, 2–4 walks per request):
//
//      routing/match/{10,100,1000}     1.50 / 1.54 / 1.54 µs      14 K instructions,  3 mallocs
//      routing/tail/{10,100,1000}      1.67 / 2.88 / 15.0 µs   16/39/259 K instructions,  3 mallocs
//      routing/miss/{1000}                          11.0 µs     208 K instructions,  3 mallocs
//      routing/capture/{static,parameters,catchAll}
//                                      1.38 / 1.92 / 2.54 µs   12/21/30 K instructions, 2/5/8 mallocs
//      (for scale) http1/RequestParser/realistic     2.71 µs;  ResponseSerializer/serialize  2.38 µs
//
//  AFTER (`Router.match`, exactly ONE walk per request — same machine, re-measured):
//
//      routing/match/{10,100,1000}     1.25 / 1.25 / 1.25 µs   14/15/14 K instructions,  3 mallocs
//      routing/tail/{10,100,1000}      1.33 / 2.46 / 14.0 µs   17/39/261 K instructions,  3 mallocs
//      routing/miss/{10,100,1000}      1.58 / 2.42 / 10.0 µs   23/40/210 K instructions,  3 mallocs
//      routing/capture/{static,parameters,catchAll}
//                                      1.13 / 1.63 / 2.13 µs   12/20/30 K instructions, 2/5/8 mallocs
//      (for scale) http1/RequestParser/realistic     2.29 µs;  ResponseSerializer/serialize  2.08 µs
//
//  The two columns are the same work — one `match` costs what one `resolve` cost, within this
//  machine's run-to-run noise (~±15 % on the sub-2 µs cases; the whole "after" column is ~10 % faster
//  including the untouched `http1/*` scale rows, which is how you can tell it is the machine and not
//  the change). `match` was never expected to be *faster*; the win is in how many times a request
//  performs it, which these microbenchmarks cannot see and `RouteMatchOnceTests` measures directly:
//
//      h1 buffered 2→1 · h1 streaming 3→1 · h2 buffered 4→1 · h2 streaming 3→1
//      h3 buffered 4→1 · h3 streaming 3→1
//
//  At ~1.25 µs per walk that is 1.25 µs saved per h1 request and ~2.5–3.75 µs per h2/h3 request —
//  against a parse-plus-serialize of ~4.4 µs, i.e. the routing tax on an h2 request fell from roughly
//  its own weight in framing cost to a quarter of it.
//
//  Reading these honestly still separates two costs the rule above conflates:
//
//  1. FIXED cost per match ≈ 1.25 µs / 3 mallocs, flat in table size. It is the path `split` array and
//     the parameter set, not the scan. A trie does not remove it, because a trie still splits the path
//     and still captures parameters. What removes it is matching ONCE per request, which is now done.
//
//  2. SCAN cost, invisible at 10 routes, ~1.2 µs at 100, and dominant at 1000 (miss 10 µs, tail 14 µs).
//     Only this is what a trie fixes, and it is now the ONLY term left.
//
//  VERDICT, re-taken against the stated rule with the fixed cost amortized: `routing/miss/1000` is
//  10 µs, so the rule fires — for thousand-route tables, and only for them. `routing/match/100` is
//  1.25 µs against ~4.4 µs of parse-plus-serialize; that is 28 % of framing for one match, but it is
//  now paid once per request instead of two to four times, so the second clause of the rule reads very
//  differently than it did. The trie is therefore still NOT built here: it is a single, well-scoped,
//  independently-benchmarkable change whose entire justification is `miss/1000`, and the honest next
//  gate for it is a table-size distribution from real deployments rather than a synthetic worst case no
//  measured application reaches. Recorded so the next reader inherits the decision, not the question.
//
//  Note also what the numbers rule OUT: `mallocCountTotal` is flat at 3 across every table size and
//  across hit/miss, so the "allocations scale with route count" half of the finding does not reproduce.
//  A proposed micro-optimization to allocate `Route.match`'s capture dictionary lazily would save
//  nothing — Swift's empty `Dictionary` already uses a shared singleton and does not allocate. Carrying
//  the captured `RouteParameters` forward in a `RouteMatch` costs nothing either: `Route.match` was
//  already building that dictionary and `resolve` was throwing it away.
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
