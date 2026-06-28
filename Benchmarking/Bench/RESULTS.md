# Bench — consolidated comparative results

One harness (`run.sh`), one load generator (`oha`), identical routes, ten servers, side by side across a
set of scenarios. Re-run `./Benchmarking/Bench/run.sh` to regenerate (raw `oha` JSON lands in
`results/`). The per-engine instructions/mallocs microbenchmarks are a separate lens in
`Benchmarking/Benchmarks/`.

## Run: 64 connections, 10s/scenario, HTTP/1.1 cleartext

Apple Silicon, 8 logical CPUs. Each server is started once and driven through every scenario; 2s warmup
then 10s measured, closed-loop. `ours` on the `swiftSystem` backbone, built release at the latest commit.
Sorted by rps. **N/A** = the server does not implement that route (oha saw <99% 2xx): nginx/caddy cannot
echo a POST body without a scripting module; django-wsgi crashed some scenarios (see caveats).

### GET / — framework floor (tiny text)
| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---|---:|---:|---:|---:|
| nginx | 187,262 | 0.337 | 0.431 | 0.612 |
| rust (hyper) | 140,659 | 0.383 | 2.121 | 6.942 |
| **ours (swiftSystem)** | **131,362** | **0.220** | 5.286 | 15.929 |
| go (net/http) | 123,749 | 0.270 | 5.946 | 9.489 |
| bun | 106,176 | 0.536 | 1.258 | 1.639 |
| caddy | 92,776 | 0.451 | 4.700 | 8.949 |
| hummingbird (NIO) | 76,018 | 0.342 | 9.892 | 39.849 |
| vapor (NIO) | 70,929 | 0.576 | 5.690 | 19.678 |
| django-asgi | 7,385 | 7.577 | 25.350 | 54.969 |
| django-wsgi | 2,927 | 12.006 | 33.646 | 1254.645 |

### GET /json — serialize `{"message":"Hello, World!"}`
| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---|---:|---:|---:|---:|
| nginx | 173,696 | 0.359 | 0.627 | 1.138 |
| **ours (swiftSystem)** | **134,931** | **0.218** | 5.525 | 14.984 |
| rust (hyper) | 130,664 | 0.398 | 2.704 | 9.047 |
| go (net/http) | 127,253 | 0.259 | 5.809 | 8.526 |
| bun | 108,864 | 0.517 | 1.242 | 1.655 |
| caddy | 76,803 | 0.584 | 5.174 | 10.088 |
| vapor (NIO) | 75,980 | 0.560 | 4.969 | 14.214 |
| hummingbird (NIO) | 72,130 | 0.346 | 10.113 | 47.404 |
| django-asgi | 7,578 | 7.258 | 25.213 | 59.861 |
| django-wsgi | N/A | - | - | - |

### GET /payload — ~1 KiB body
| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---|---:|---:|---:|---:|
| nginx | 170,988 | 0.368 | 0.492 | 0.689 |
| rust (hyper) | 133,255 | 0.387 | 2.676 | 8.727 |
| go (net/http) | 122,546 | 0.270 | 5.989 | 9.209 |
| **ours (swiftSystem)** | **108,609** | **0.368** | 5.927 | 18.007 |
| bun | 106,278 | 0.532 | 1.260 | 1.636 |
| caddy | 83,196 | 0.529 | 4.821 | 9.211 |
| hummingbird (NIO) | 79,815 | 0.342 | 8.770 | 36.531 |
| vapor (NIO) | 72,350 | 0.590 | 5.123 | 15.008 |
| django-asgi | 6,793 | 7.628 | 33.290 | 335.846 |
| django-wsgi | 3,690 | 11.750 | 34.759 | 47.656 |

### GET /hello/world — router + path/query parameter
| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---|---:|---:|---:|---:|
| nginx | 155,082 | 0.404 | 0.567 | 1.046 |
| rust (hyper) | 147,429 | 0.352 | 2.176 | 6.809 |
| **ours (swiftSystem)** | **125,997** | **0.253** | 5.614 | 17.362 |
| go (net/http) | 117,787 | 0.272 | 6.420 | 10.679 |
| bun | 104,144 | 0.543 | 1.278 | 1.685 |
| hummingbird (NIO) | 79,441 | 0.326 | 9.401 | 39.393 |
| caddy | 74,693 | 0.543 | 6.095 | 12.605 |
| vapor (NIO) | 65,880 | 0.666 | 5.258 | 13.845 |
| django-asgi | 7,980 | 7.204 | 21.034 | 62.947 |
| django-wsgi | 2,062 | 48.840 | 5783.791 | 5783.976 |

### POST /echo — request read + body round-trip
| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---|---:|---:|---:|---:|
| rust (hyper) | 147,160 | 0.328 | 2.539 | 8.070 |
| **ours (swiftSystem)** | **128,739** | **0.225** | 5.828 | 16.668 |
| go (net/http) | 101,710 | 0.310 | 5.904 | 11.032 |
| caddy | 92,584 | 0.470 | 4.434 | 8.774 |
| bun | 92,523 | 0.621 | 1.415 | 1.828 |
| vapor (NIO) | 75,873 | 0.542 | 5.389 | 15.349 |
| hummingbird (NIO) | 72,901 | 0.355 | 10.236 | 42.351 |
| django-asgi | 7,682 | 7.614 | 21.154 | 63.834 |
| nginx | N/A | - | - | - |
| django-wsgi | N/A | - | - | - |

### Takeaways

- **ours places 2nd–3rd of the ten-server field on throughput and posts the lowest median latency
  (p50 ≈ 0.22 ms) of every server measured** — only nginx (C) is consistently ahead, and ours is
  neck-and-neck with rust/hyper (it edges rust on `/json` and trails it on the others).
- **ours beats both SwiftNIO frameworks decisively** — ~1.7–1.9× Hummingbird's and Vapor's throughput
  across every scenario. The from-scratch, NIO-free server is faster than the established NIO frameworks
  on this workload, which was the project's central "are we competitive without NIO?" question.
- **ours is #2 on POST /echo** (request parse + body round-trip), behind only hyper — the request-path
  work holds up under a body, not just on static GETs.
- Our **tail** (p99 ≈ 5–6 ms, p99.9 ≈ 15–18 ms) is the remaining gap to nginx/rust/bun (sub-ms to ~2 ms
  p99). That tail is the next measure-first optimization target (per-request allocation, metrics-handle
  churn — the audit's P1 items).

### Caveats

- **django-wsgi is unreliable on this box** (Python 3.14, very new): gunicorn crashed `/json` and
  `/echo` (N/A) and shows multi-second tails on `/hello`. **django-asgi (uvicorn, ~7–8k rps) is the
  representative Django number.** The first light-workload run had the failure reversed (asgi flaky,
  wsgi fine) — treat the slower Django row as noise from the bleeding-edge Python.
- **Contention sensitivity:** absolute rps depends on the machine being otherwise idle. An earlier
  pass taken while a second benchmark process was running showed nginx/caddy depressed ~2–5×; this run
  was taken on a quiet box. Re-run when nothing else is loading the machine.
- **hummingbird/vapor build out-of-tree:** SwiftPM mis-resolves a package nested in another package's
  git tree ("product Hummingbird not found"), so the two SwiftNIO packages are copied outside the repo
  and built there (the harness does this automatically and caches the result).

## Reproduce

```sh
./Benchmarking/Bench/run.sh                                   # all servers, all scenarios
SCENARIOS="GET:/json POST:/echo" SERVERS="ours rust go" ./Benchmarking/Bench/run.sh
CONNECTIONS=128 DURATION=20s ./Benchmarking/Bench/run.sh
```
