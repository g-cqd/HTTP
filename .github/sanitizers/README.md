# Linux sanitizer runtime checks

## Thread Sanitizer

The pinned Swift 6.4 Linux runtime ships `Synchronization` without Thread Sanitizer
instrumentation. Under contention, `Mutex` calls its compiled slow path. TSan cannot
observe that path's atomic acquire, and reports a race on correctly locked values.
The same standalone locked-counter reproduction also fails with Swift 6.4.2
(`2d23cd0ab559aed`) and Swift 6.5 development (`2abb962c344c545`). A similar Linux `Mutex` report is
recorded in [the Swift forums](https://forums.swift.org/t/threadsanitizer-in-a-swift-concurrency-world/84801).

`build-linux-tsan-runtime.sh` rebuilds the matching
[upstream `Synchronization` sources](https://github.com/swiftlang/swift/tree/80702ec6ad4159b69f624ef4a814946b16237379/stdlib/public/Synchronization)
without modifying them. It checks the compiler revision, preserves the
installed runtime's exported symbols, and leaves the installed module untouched.
The image digest and source revision must be updated together.

The compiler crashes when instrumenting two source files directly:

- `Mutex.swift`: its generic inout body triggers a TSan SILGen assertion. Every
  method is transparent and emitted into clients, so instrumented test binaries
  still check those methods.
- `SpinLoopHint.swift`: TSan generates invalid LLVM IR for the CPU hint intrinsic.
  This file performs no memory access.

All other runtime source files, including the atomic operations used by the slow
path, are instrumented. No TSan report is suppressed. Before the HTTP suite runs,
`check-linux-tsan-runtime.sh` requires the locked counter to succeed and a deliberate
unlocked race to fail with a TSan race report. The executable exports its sanitizer
symbols so the separately loaded runtime can resolve them.
The test executable's library search path selects this runtime; SwiftPM and the
installed toolchain keep their normal runtime.

## Leak Sanitizer

`lsan-linux.supp` applies only to the Linux Address Sanitizer leg. It covers the
Foundation `Process.run()` weak-reference side-table false positive associated
with [LLVM issue 56751](https://github.com/llvm/llvm-project/issues/56751).
One and one hundred completed `Process` calls both report the same 32 bytes;
an independent heap-leak control still fails with the exception enabled.
