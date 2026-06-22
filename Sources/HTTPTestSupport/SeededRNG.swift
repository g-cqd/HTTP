//
//  SeededRNG.swift
//  HTTPTestSupport
//
//  A deterministic, seedable generator for property tests and fuzz corpora — so a parser fuzz run
//  that pins a seed reproduces the exact same inputs every run, on every machine.
//

/// A deterministic SplitMix64 generator (RandomNumberGenerator), seeded for reproducibility.
public struct SeededRNG: RandomNumberGenerator, Sendable {
    private var state: UInt64

    /// Seeds from a raw 64-bit value.
    public init(seed: UInt64) { self.state = seed }

    /// Seeds from a ``Seed`` — a raw value or a stable name.
    public init(seed: Seed) { self.state = seed.rawValue }

    /// Seeds directly from a stable name.
    public init(named name: String) { self.init(seed: Seed.named(name)) }

    /// The SplitMix64 core (published constants), so a pinned seed reproduces the same stream.
    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    /// A value in `0 ..< bound` (`bound > 0`).
    ///
    /// The modulo bias is irrelevant to a fuzz corpus and keeps the stream fully deterministic.
    public mutating func uniform(_ bound: Int) -> Int {
        precondition(bound > 0, "SeededRNG.uniform requires a positive bound")
        return Int(next() % UInt64(bound))
    }

    /// A value in `0 ..< bound`.
    public mutating func below(_ bound: Int) -> Int { uniform(bound) }

    /// A value in `lower ... upper` inclusive.
    ///
    /// The span is computed in 64-bit unsigned space, so even the extreme ranges (`0 ... .max`,
    /// `.min ... .max`) draw without trapping on the `upper - lower + 1` overflow the naive form hits.
    public mutating func int(in range: ClosedRange<Int>) -> Int {
        let span = UInt64(
            bitPattern: Int64(truncatingIfNeeded: range.upperBound &- range.lowerBound))
        if span == .max { return Int(truncatingIfNeeded: next()) }  // the full Int range
        let offset = next() % (span &+ 1)
        return range.lowerBound &+ Int(truncatingIfNeeded: offset)
    }

    /// A uniformly chosen element (`items` must be non-empty).
    public mutating func pick<T>(_ items: [T]) -> T { items[uniform(items.count)] }

    /// `true` when the low bit of ``next()`` is clear.
    public mutating func bool() -> Bool { next() & 1 == 0 }

    /// The low byte of ``next()``.
    public mutating func byte() -> UInt8 { UInt8(truncatingIfNeeded: next()) }
}

/// A named or raw seed for reproducible randomness.
///
/// `Seed.named(_:)` derives a stable 64-bit value from a name (FNV-1a over the UTF-8 bytes —
/// process-independent, unlike `Hasher`), so a suite can replace a scattered magic constant with a
/// self-documenting `Seed.named("http1.request-parser")` and still reproduce the same stream.
public struct Seed: Sendable, Hashable, RawRepresentable {
    /// The raw 64-bit seed value.
    public let rawValue: UInt64

    /// Creates a seed from a raw value.
    public init(rawValue: UInt64) { self.rawValue = rawValue }

    /// Creates a seed from a raw value.
    public init(_ rawValue: UInt64) { self.rawValue = rawValue }

    /// A stable, process-independent seed derived from `name` (FNV-1a, no `Hasher` randomization).
    public static func named(_ name: String) -> Seed {
        var hash: UInt64 = 0xCBF2_9CE4_8422_2325  // FNV-1a 64 offset basis
        for byte in name.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3  // FNV-1a 64 prime
        }
        return Seed(rawValue: hash)
    }
}
