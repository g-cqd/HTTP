# ADR 0008 — Static-file blocking work rides the handler execution seam

- **Status:** Accepted. No new executor is added. One gap is left open with a pre-registered rule for
  closing it (see *The gap this does not close*).
- **Context date:** 2026-08
- **Supersedes nothing. Depends on** ADR 0007 (handler execution policy).

## Context

The 2026-07-31 performance addendum, "Static serving performs blocking filesystem work on the
reactor", lists the syscalls and asks for a remedy:

> Path walking, `openat`, `fstat`, small-file `pread`, streaming `pread`, and directory enumeration
> are synchronous inside the handler hierarchy and can therefore block a reactor. Use a dedicated
> bounded blocking-I/O pool and a metadata/descriptor cache with explicit invalidation bounds.

The syscalls are real and the file references are accurate. Every one of them is a synchronous libc
call on whatever thread the handler is running on, and on the four loop-backed backbones that thread
is a serial event loop:

| site | file | syscalls |
|---|---|---|
| resolution walk | `RootDirectory.resolve/leaf` | `fcntl`, one `openat` per path component (≤ 32), `fstat`, `close` |
| index lookup | `OpenedDirectory.openFile` | `openat`, `fstat` |
| sidecar probes | `FileResponder+Precompressed.sidecar` | up to two `openat` + `fstat` |
| sub-threshold body | `OpenedFile.read` | a `pread(2)` loop, up to 1 MiB |
| streamed body | `FileRegionStreamer.stream` | one `pread(2)` per 64 KiB chunk |
| autoindex | `FileResponder+Autoindex.entries/entry` | `fdopendir`, N × `readdir`, N × `fstatat` — the one unbounded site |

The addendum's remedy is a **second** executor concept. ADR 0007 shipped the first one three weeks
earlier, deliberately at `.inline`, and deliberately as *one* decision routed through one function.
Adding a second placement without establishing that the first does not fit would leave three answers
to one question.

So the question was measured rather than argued.

## What the existing seam already covers

`HandlerExecutionPolicy` wraps the `respond` call. `FileResponder` *is* the responder, so everything
it does while answering is inside that wrap: the resolution walk, the index lookup, the sidecar
probes, the sub-threshold `pread`, and the autoindex `readdir`/`fstatat` loop. Under `.concurrent`
all of it leaves the reactor today, with no new machinery.

The `ResponseStream` producer is **not** covered. ADR 0007 records that the preference is restored
when the hopped operation returns — "the restore in the last line is what puts the response write
back on the owning reactor" — and the engine drives the producer *after* `respond` returns. So the
streaming `pread` pump stays on the reactor under every policy.

Both facts are pinned executably by `StaticFileExecutionPlacementTests`, using ADR 0007's own
`ReactorProbeExecutor`, rather than inferred from the call graph. Inferring it gets it half right,
which is the worst of the three possible outcomes.

## Decision

**Static-file blocking work rides `HandlerExecutionPolicy`. No blocking-I/O executor is added.**

Reasons, in order of weight:

1. **The first mechanism fits the majority of the finding.** Five of the six sites in the table are
   inside `respond` and already follow the policy. A second executor would relocate work that the
   first executor already relocates, and a deployment would then have to reason about which of two
   knobs moved which syscall.
2. **The sixth site cannot be fixed by a pool either.** The streaming `pread` is not on the reactor
   because it lacks a pool to run on; it is there because the *seam* ends at `respond`. Handing it to
   a blocking pool requires exactly the same restructuring as handing it to the cooperative pool —
   see the open item below — so the pool is not what is missing.
3. **This host cannot adjudicate it.** ADR 0007 recorded a 1.80× throughput spread across three
   consecutive rounds of one configuration, and declined to flip its own default on a clause that
   failed by one percentage point. An executor-topology change whose entire justification is a
   throughput and tail-latency claim cannot be landed on evidence this host can produce.

Recorded honestly, the argument **for** a dedicated blocking pool, so it is not lost:

> `.concurrent` hops to `globalConcurrentExecutor`, which is the cooperative pool. Its width is the
> core count, and blocking one of its threads in `pread(2)` is the documented hazard the pool exists
> to avoid. `.concurrent` therefore trades "stall one reactor shard" for "consume one cooperative
> thread" — better, but not the ideal, and ADR 0007 already says so in its own consequences
> ("`.concurrent` relocates the blocking damage, it does not remove it"). A dedicated pool of threads
> that are *allowed* to block would remove it. That is a real improvement and it is deferred, not
> dismissed.

**Not attempted:** the metadata/descriptor cache the addendum also asks for. It needs an invalidation
design with explicit bounds (`st_dev`/`st_ino`/`mtime` staleness, and a cap that is not
attacker-chosen), and mixing it into an execution-placement decision would produce a change nobody
could review.

## The gap this does not close

The `ResponseStream` producer runs on the reactor under every policy. For static files that means the
64 KiB `pread` pump; since streaming response compression landed it also means **per-chunk deflate**,
which is CPU rather than a syscall and therefore worse.

Two things bound the exposure today:

- On HTTP/1.1, a file region with a known `Content-Length` goes out via `sendfile(2)` — one syscall,
  not a pump. The pump is reached only when the body is chunked, when the backbone has no
  `sendfile(2)`, or on h2/h3.
- h2's and h3's stream producers are not reactor-pinned in the first place: h2's streaming-route head
  runs inside an unstructured `Task`, which ADR 0007 measured as *not* inheriting the preference, and
  HTTP/3 has no preference at all because a QUIC connection is not a `TransportConnection`.

So the exposure is specifically: **HTTP/1.1, a chunked or compressed streamed body, on a loop-backed
backbone.** Compression makes that case more common, and that is a cost of the compression change,
stated here rather than left to be discovered.

Closing it requires the producer to hop while the *writes* stay on the reactor — ADR 0007's
invariant, pinned by `HandlerExecutionReactorAffinityTests`, is that socket I/O never leaves the
owning loop. That means `withTaskExecutorPreference` around `stream.produce`, plus a return hop
around every `connection.send` in `H1StreamWriter`: two executor transitions per body chunk, on a
path whose chunks are 64 KiB. It also means threading the policy decision (including `.adaptive`'s
per-route verdict, which is keyed on a `RouteMatch.Handle` the streaming path does not currently
carry) down to `sendStreamedResponse`.

### Pre-registered rule for closing it

**Recorded before any measurement, so the verdict cannot be retrofitted.**

> Adopt the producer hop **only if all three hold**, on a quiesced host with no other tenant above a
> few percent, ROUNDS ≥ 5 and a reported round-to-round spread under 5 %:
>
> 1. streamed-response throughput under `.inline` regresses by **less than 2 %** (the hop is a no-op
>    under the shipped default, so any regression there is pure overhead), and
> 2. under `.concurrent`, a 90/10 mix of trivial requests and 64 MiB compressed streamed downloads
>    improves trivial-route p99 by **more than 2×**, and
> 3. streamed-download throughput under `.concurrent` regresses by **less than 10 %** against
>    `.inline`.
>
> If clause 2 fails, the gap is not worth the two hops per chunk and this ADR stands as written.

Clause 2 is set at the same bar as ADR 0007's clause 3 and for the same reason: the failure mode is a
stalled shard, which should show up as a difference of kind rather than of degree.

## Consequences

- No public API changes. No new configuration. `HandlerExecutionPolicy` remains the only answer to
  "where does non-reactor-owned work run", and remains `.inline` by default.
- A deployment that serves large static files from a loop-backed backbone and cares about reactor
  occupancy should set `.concurrent`, which now demonstrably covers the resolution walk, the sidecar
  probes, the sub-threshold `pread` and the autoindex loop.
- The autoindex path stays the sharpest remaining site: its syscall count is one `readdir` plus one
  `fstatat` per directory entry, with no bound. It is off by default (`autoindex: false`), which is
  why it is not escalated here, but a deployment that enables it over a large directory should assume
  `.concurrent`.
- `StaticFileExecutionPlacementTests` will fail if the seam ever grows to cover stream production.
  That is the intended signal: the fix is to update this ADR, not the expectation.
