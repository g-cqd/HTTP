# Results — Swift HTTP server vs Django

A snapshot from `./run.sh`. **Absolute numbers are soft** (laptop, thermal drift under a ~10 min
sustained matrix); the **within-run factors and the shape across scenarios** are the result. Re-run on a
pinned host for trustworthy absolutes. Methodology, fairness notes, and caveats: [`README.md`](README.md).

| | |
|---|---|
| **Host** | Apple M3 · 8 cores (4P + 4E) · 16 GB · macOS 26.5 |
| **Subject** | this repo's `HTTPServer`, cleartext HTTP/1.1, Swift 6.4, `-c release` |
| **Django** | 6.0.6 · gunicorn (WSGI, sync views) · uvicorn 0.49 + uvloop/httptools (ASGI, async views) · Python 3.14.6 · `DEBUG=False` |
| **Load** | `oha` 1.14 · 3 s warmup + 10 s measured per cell · loopback · every cell `ok = 100%` |
| **Date** | 2026-06-25 |

## TL;DR

Across all five use cases, on the request/response hot path the two share, the Swift server delivers
roughly **7–14× the throughput** and **6–14× lower per-request latency** of the *best-configured* Django
stack — and stays flat under load (p50 ≈ 0.05 ms, p99 < 0.2 ms serialized) where Django's tail blows out
(p99 75–280 ms at the throughput ceiling). This is an expected weight-class gap — Django is a full
batteries-included framework, not an HTTP server — but the *factor* is the useful number.

- **Throughput ceiling (all cores):** ours **28.8k–47.9k rps**; best Django **2.0k–4.0k rps**.
- **Per-request cost (1 worker, serialized):** ours **46–60 µs**; best Django **274 µs–1.0 ms**.
- The two Django stacks trade places by scenario: **ASGI/uvicorn** wins on kept-alive per-request
  latency; **WSGI/gunicorn** sometimes edges it at the ceiling. Neither closes the gap to native.

## Ceiling — all cores (Django workers = 8, `oha -c 64`)

"What can each actually serve on this box?" Read **rps** (higher better); p99 is the tail under load.

| scenario | ours rps | django-wsgi rps | django-asgi rps | **ours ÷ best Django** | ours p99 | best-Django p99 |
|---|---:|---:|---:|:---:|---:|---:|
| plaintext | **47,887** | 3,780 | 2,839 | **12.7×** | 25.6 ms | 90.3 ms |
| json | **34,935** | 4,148 | 2,953 | **8.4×** | 33.7 ms | 91.9 ms |
| routing | **36,822** | 1,956 | 2,578 | **14.3×** | 33.8 ms | 143.8 ms |
| echo (POST) | **28,814** | 2,142 | 4,020 | **7.2×** | 43.0 ms | 75.3 ms |
| middleware | **32,039** | 2,312 | 2,042 | **13.9×** | 32.8 ms | 116.4 ms |

## Efficiency — per request (Django workers = 1, `oha -c 1`, serialized)

Neither side uses extra cores here, so this isolates **per-request framework cost**. Read **p50 latency**
(lower better); rps is just `1000 / p50ms` at one connection.

| scenario | ours p50 | django-wsgi p50 | django-asgi p50 | **best Django ÷ ours** | ours p99 |
|---|---:|---:|---:|:---:|---:|
| plaintext | **0.046 ms** | 0.382 ms | 0.520 ms | **8.3×** | 0.18 ms |
| json | **0.049 ms** | 0.390 ms | 0.291 ms | **5.9×** | 0.15 ms |
| routing | **0.048 ms** | 0.733 ms | 0.274 ms | **5.7×** | 0.17 ms |
| echo (POST) | **0.051 ms** | 0.510 ms | 0.298 ms | **5.8×** | 0.10 ms |
| middleware | **0.060 ms** | 1.009 ms | 0.814 ms | **13.6×** | 0.10 ms |

## Reading the results

- **The gap is structural, not a single bottleneck.** It holds across plaintext, JSON, routing, body
  parsing, and a middleware chain — i.e. it's the cost of CPython + a per-request Python call stack vs.
  compiled Swift, not one slow feature. The middleware scenario widens it most (13.6× per-request),
  because every middleware is another Python frame on both request and response.
- **Tail latency is where it's starkest.** Serialized, ours holds p99 < 0.2 ms; at the ceiling its p99 is
  tens of ms (closed-loop queueing + thermal throttling). Django's p99 is 75–280 ms at the ceiling —
  the GIL serializes work and requests pile up behind the busy workers.
- **WSGI vs ASGI.** uvicorn (ASGI, kept-alive) generally gives Django its **best per-request latency**
  (json/routing/echo ≈ 0.27–0.30 ms). gunicorn (WSGI, sync) has **no keep-alive**, so its single-
  connection numbers pay TCP setup every request (routing/middleware p99 spikes to 12–15 ms) — but its
  pre-fork model sometimes wins the ceiling. Running both was worth it: the story isn't "async fixes it."
- **Echo is Django's best scenario relative to ours** (7.2× at the ceiling) — JSON parsing is C-backed
  (`json` module) on Django's side and `JSONSerialization`/Foundation on ours, so more of the work
  happens in compiled code for both, narrowing the gap. Swapping ours' JSON engine to the local
  **ADJSON** library makes our JSON work ~1.7× faster on realistic (tens-of-KB) bodies — see
  [ADJSON.md](ADJSON.md) — though at these tiny payloads it's a wash.

## Caveats (full list in README)

- **Soft absolutes.** Sustained back-to-back runs warmed the M3; ours plaintext measured **146k rps**
  cold in a one-off slice vs **48k** mid-matrix. The matrix is internally consistent (all cells warm,
  back-to-back), so the **factors** stand; the **absolutes** do not. Pin/cool the host to trust those.
- **Weight class.** This measures only the HTTP request/response path. Django's value (ORM, admin,
  migrations, auth, templating, forms) is out of frame and not what's being weighed.
- **Loopback, no DB.** No network and no database — add a DB and both collapse toward DB latency; this is
  the framework-overhead comparison, deliberately.

## Reproduce

```sh
cd Benchmarking/Django
./run.sh                                  # full matrix (~10–15 min)
SCENARIOS="plaintext json" CALIBRATIONS=ceiling ./run.sh   # a quick slice
```
