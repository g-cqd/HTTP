//
//  Seed.swift
//  HTTPTestSupport
//
//  A named or raw seed for reproducible randomness — so a suite can replace a scattered magic
//  constant with a self-documenting `Seed.named("http1.request-parser")` and still reproduce the
//  same stream on every machine.
//

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
    public static func named(_ name: String) -> Self {
        var hash: UInt64 = 0xCBF2_9CE4_8422_2325  // FNV-1a 64 offset basis
        for byte in name.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3  // FNV-1a 64 prime
        }
        return Self(rawValue: hash)
    }
}
