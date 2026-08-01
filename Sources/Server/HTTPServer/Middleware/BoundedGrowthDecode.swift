//
//  BoundedGrowthDecode.swift
//  HTTPServer
//
//  The decompression-bomb bound (CWE-409) for the ONE-SHOT decode shims: `InflateLinux` (zlib, over
//  `CZlibCoding`) and `BrotliLinux` (libbrotli, over `CBrotli`). Both wrap a C entry point that
//  decodes a whole stream into a caller-sized destination and cannot say "would not fit" other than
//  by failing, so both have to retry into a larger destination — which is where the bound lives.
//
//  It lives here, once, because it was written twice and the copies had already started explaining
//  themselves by reference to each other ("for the same reasons as InflateLinux, which carries the
//  full note"). A safety bound that exists in two places is a bound that will be fixed in one.
//
//  The Darwin path (`Inflate.swift`, Apple's Compression framework) is deliberately NOT a caller: it
//  enforces the bound *during* an incremental pump and never retries, which is a different — and
//  strictly better — shape. This is the fallback for shims that cannot stream.
//

/// The retry schedule shared by the one-shot decompression shims (CWE-409).
enum BoundedGrowthDecode {
    /// The first destination size tried, in octets.
    ///
    /// 64 KiB covers the overwhelming majority of real coded bodies in a single attempt, so the
    /// geometric path below is the exception rather than the rule.
    static let window = 64 * 1_024

    /// Runs `attempt` against geometrically growing destinations, never exceeding `maxOutput`.
    ///
    /// Returns the first attempt's output, or `nil` once a destination of exactly `maxOutput` octets
    /// has failed — the fail-closed decompression-bomb defense (CWE-409).
    ///
    /// The destination grows from ``window`` rather than being sized to the cap for two measured
    /// reasons. Sizing to the cap charged **every** request the cap: a small coded body under a
    /// default-scale limit allocated hundreds of megabytes. And the older "did it fit" test computed
    /// `maxOutput + 1`, which overflows at `Int.max`. Growing instead means the last attempt is sized
    /// to `maxOutput` *exactly*, so a body over the cap simply never fits — the fail-closed signal,
    /// with no `+ 1` to overflow and no allocation proportional to the limit rather than the body.
    ///
    /// The trade is CPU: a one-shot shim re-decodes from the start on each step, costing about twice
    /// the decode of the final size, across at most `log2(maxOutput / window)` attempts.
    ///
    /// Termination: `capacity` is strictly increasing (it doubles only where doubling provably stays
    /// within the cap, and otherwise jumps to `maxOutput`), and the loop exits as soon as an attempt
    /// at `maxOutput` has been made — so the number of attempts is bounded by that logarithm plus
    /// one, for every `maxOutput` including `Int.max`.
    static func run(maxOutput: Int, attempt: (Int) -> [UInt8]?) -> [UInt8]? {
        guard maxOutput > 0 else {
            return nil
        }
        var capacity = min(window, maxOutput)
        while true {
            if let output = attempt(capacity) {
                return output
            }
            guard capacity < maxOutput else {
                return nil
            }
            // `capacity * 2` only where it provably stays within the cap, so it cannot overflow.
            capacity = capacity <= maxOutput / 2 ? capacity * 2 : maxOutput
        }
    }
}
