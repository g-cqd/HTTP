# Django comparison — the Swift HTTP server vs Django

An end-to-end comparison of this repo's Swift HTTP server against **Django**, the reference Python web
framework, across a matrix of common use cases. It drives all three servers with the **same** load
generator (`oha`) on **identical** routes and reports throughput (rps) and tail latency (p50/p99/p99.9)
side by side.

This is a different axis from [`../Bench`](../Bench), which pits the server against C/Go/SwiftNIO HTTP
servers (nginx, Caddy, Hummingbird) on a bare route. Here the yardstick is a *full web framework* — so
the interesting question is not "are we as fast as nginx?" but **"what does a native Swift stack buy you
over a typical Python web app, and where?"** The two are in different weight classes; that gap is the
point.

> **Iron Law (inherited from `../Bench`).** Measure, don't guess. Report **percentiles, not averages**,
> run in **release**, pin the workload, and serve each framework in its own idiom. Absolutes are soft on
> a thermally-throttled laptop; trust the **within-run ranking** and the **shape across scenarios**.

## The three subjects

| label | what | served by | views |
|---|---|---|---|
| **ours** | this repo's `HTTPServer`, cleartext HTTP/1.1 | `ours/` (SwiftPM, release) | the `Router` DSL |
| **django-wsgi** | Django on the classic synchronous stack | `gunicorn` (WSGI) | `def` (sync) |
| **django-asgi** | Django on the modern async stack | `uvicorn` + uvloop/httptools (ASGI) | `async def` |

Both Django stacks run the **same app** (`djangoapp/benchsite`); only the server and the view flavor
differ — `urls.py` picks the sync or async view set from `BENCH_ASYNC`. `ours-bench` mirrors every route
byte-for-byte in intent.

## Scenarios

Each is implemented identically on both sides (`ours/Sources/ours-bench/main.swift` ↔
`djangoapp/benchsite/views.py`):

| scenario | request | exercises |
|---|---|---|
| `plaintext` | `GET /` → `"Hello, World!"` | framework-overhead floor |
| `json` | `GET /json` → `{"message": "Hello, World!"}` | serialize a small object (`.json` ↔ `JsonResponse`) |
| `routing` | `GET /hello/world?greeting=Hi` | router + path **and** query parameter extraction |
| `echo` | `POST /echo` with a JSON body | request-body read + JSON parse + re-serialize |
| `middleware` | `GET /payload` (~1 KiB) with `Accept-Encoding: gzip` | a realistic middleware chain on a body worth compressing |

The `middleware` scenario turns on a comparable response-shaping chain on **both** sides
(`BENCH_MIDDLEWARE=1`): gzip, a `Server`/`Date` header, security headers, a CORS header, and an
ETag/conditional-GET pass.

| ours (`MiddlewareChain`) | Django (`MIDDLEWARE`) |
|---|---|
| `CompressionMiddleware` (gzip) | `django.middleware.gzip.GZipMiddleware` |
| `SecurityHeadersMiddleware` | `django.middleware.security.SecurityMiddleware` |
| `CORSMiddleware` | a small `cors_middleware` (sync+async aware) |
| `ConditionalRequestMiddleware` (ETag) | `django.middleware.http.ConditionalGetMiddleware` |
| `ServerHeaderMiddleware` / `DateHeaderMiddleware` | server-supplied / `CommonMiddleware` |

## Two calibrations per scenario

Django is **GIL-bound**: one worker process ≈ one CPU core. Our server has no GIL and uses every core in
one process. Comparing them at a single operating point would be misleading, so every scenario is run
twice:

- **ceiling** — every server uses the whole machine (Django `--workers = CPU cores`; ours multi-core),
  closed-loop at high concurrency (`-c 64`). Answers **"what can each actually serve on this box?"** —
  the headline throughput number.
- **efficiency** — one Django worker, one serialized connection (`-c 1`). At a single in-flight request
  neither side benefits from extra cores, so this isolates **per-request framework cost**. Read **p50
  latency** here, not rps (rps is just `1000 / p50ms`).

## Quick start

```sh
brew install oha jq                 # load generator + JSON parsing
./run.sh                            # full matrix (~10–15 min); builds ours + the .venv on first run
```

First run builds `ours-bench` (release) into `/tmp/swiftpm-build/ours-bench`, creates `.venv`, and
`pip install`s `requirements.txt` (Django + gunicorn + uvicorn[standard]). Re-runs reuse both.

Knobs (all env vars):

| var | default | meaning |
|---|---|---|
| `SCENARIOS` | `plaintext json routing echo middleware` | which use cases to run |
| `CALIBRATIONS` | `ceiling efficiency` | which calibrations to run |
| `SERVERS` | `ours django-wsgi django-asgi` | which subjects to run |
| `DURATION` | `10s` | measured wall-clock per cell |
| `WARMUP` | `3s` | throwaway pre-measurement pass (`0` skips) |
| `CEIL_CONN` | `64` | ceiling concurrency (`oha -c`) |
| `CEIL_WORKERS` | `$(sysctl hw.ncpu)` | Django workers for the ceiling run |
| `GUNICORN_WORKER_CLASS` | `sync` | `sync` (classic) or `gthread` (adds keep-alive) |
| `OURS_JSON` | `foundation` | our `/json`+`/echo` JSON engine: `foundation` or `adjson` (see [ADJSON.md](ADJSON.md)) |

```sh
# just the floor, both calibrations:
SCENARIOS="plaintext json" ./run.sh
# only the async Django stack, longer window:
SERVERS="ours django-asgi" DURATION=20s ./run.sh
```

## Methodology & caveats

- **Release only.** `ours-bench` is built `-c release`; Django runs `DEBUG=False` with no DB, no apps,
  and no templates (the scenarios are pure request/response). DEBUG=True is much slower and would be
  fiction.
- **Loopback.** Everything hits `127.0.0.1`, so the NIC is out of the picture — this isolates
  framing/IO/serialization cost, not network throughput.
- **Same workload, native idioms.** Identical routes and payloads on every server, but each Django stack
  runs in its own idiom: sync views under WSGI, async views under ASGI. We do **not** emulate one on the
  other.
- **gunicorn sync has no keep-alive.** The classic `sync` worker closes the connection after each
  response (people front it with nginx/uvicorn for keep-alive), so `django-wsgi` pays TCP setup that
  `ours` and `django-asgi` amortize over a kept-alive connection. That is realistic for the most common
  Django deployment; `GUNICORN_WORKER_CLASS=gthread` enables keep-alive if you want to factor it out.
  The `--threads 4` we pass only matters for `gthread`.
- **GIL → worker count is the dial.** Django throughput scales with worker **processes**, so the ceiling
  run gives it `--workers = cores`. These views are CPU-bound (no IO/DB), so more workers than cores
  would only add context-switching, not throughput.
- **JSON bytes differ slightly.** Django's `JsonResponse` emits `{"k": v}` (spaces); our `.json` via
  `JSONSerialization` emits `{"k":v}`. Both perform a real encode of the same object — the few extra
  bytes are each encoder's own formatting, not a thumb on the scale.
- **Absolutes are soft; rankings are firm.** On a laptop, repeated runs can swing in absolute rps from
  thermal drift. The `ok%` column flags any run where non-2xx responses crept in (it should read 100).
- **Not a Django teardown.** Django is a batteries-included framework (ORM, admin, auth, templating,
  migrations) doing far more than an HTTP server. This measures only the request/response hot path the
  two have in common. A native stack winning on raw rps is expected; the useful output is the *factor*
  and how it shifts across scenarios and calibrations.

Raw `oha` JSON (per `scenario__calibration__server.json`) and each server's log land in `results/`
(git-ignored).
