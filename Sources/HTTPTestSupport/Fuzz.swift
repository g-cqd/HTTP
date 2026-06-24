//
//  Fuzz.swift
//  HTTPTestSupport
//
//  A seeded byte-mutation fuzz driver for the sans-I/O parsers: the PASS condition is process
//  survival — a typed parse error or `nil` is expected-and-fine, and only a trap (precondition /
//  fatalError / OOB / stack overflow) fails the run by aborting it. Iterative; no recursion.
//

internal import Foundation

/// A seeded byte-mutation engine: overwrite / bit-flip / truncate / extend.
public struct ByteMutator: Sendable {
    /// The four mutation shapes a corrupt blob takes.
    public enum Edit: Sendable, Hashable, CaseIterable {
        case overwrite
        case bitFlip
        case truncate
        case extend
    }

    /// One applied edit, for a repro trace line.
    public struct Mutation: Sendable, CustomStringConvertible {
        /// Which edit shape was applied.
        public let kind: Edit
        /// The byte offset the edit touched, if applicable.
        public let offset: Int?
        /// The byte value written, for an overwrite.
        public let value: UInt8?

        /// A compact repro description (e.g. `set@12=0xff`).
        public var description: String {
            switch kind {
                case .overwrite:
                    "set@\(offset ?? -1)=0x\(String(value ?? 0, radix: 16))"
                case .bitFlip:
                    "flip@\(offset ?? -1)"
                case .truncate:
                    "truncate"
                case .extend:
                    "extend"
            }
        }
    }

    /// The sub-range overwrite / bit-flip may touch (and the floor truncate may not shrink below);
    /// `nil` = the whole buffer.
    public var region: Range<Int>?

    /// Which edit shapes to draw from (default: all four, in declaration order).
    public var allowedEdits: [Edit]

    /// Maximum tail bytes a single `extend` appends (default 64).
    public var maxExtend: Int

    /// Creates a mutator.
    public init(
        region: Range<Int>? = nil, allowedEdits: [Edit] = Edit.allCases, maxExtend: Int = 64
    ) {
        self.region = region
        self.allowedEdits = allowedEdits.isEmpty ? Edit.allCases : allowedEdits
        self.maxExtend = maxExtend
    }

    /// Applies `count` edits to `bytes` in place, returning the list for a repro trace.
    ///
    /// A selected overwrite/bit-flip/truncate whose guard fails falls through to `extend`. Iterative —
    /// no recursion.
    @discardableResult
    public func apply(
        _ count: Int, to bytes: inout [UInt8], using rng: inout SeededRNG
    )
        -> [Mutation]
    {
        var applied: [Mutation] = []
        applied.reserveCapacity(count)
        let truncateFloor = region?.lowerBound ?? 1
        for _ in 0 ..< count {
            let kind = allowedEdits[rng.below(allowedEdits.count)]
            switch kind {
                case .overwrite where !bytes.isEmpty:
                    let index = pickIndex(bytes.count, &rng)
                    let value = rng.byte()
                    bytes[index] = value
                    applied.append(Mutation(kind: .overwrite, offset: index, value: value))
                case .bitFlip where !bytes.isEmpty:
                    let index = pickIndex(bytes.count, &rng)
                    bytes[index] ^= UInt8(1 << rng.below(8))
                    applied.append(Mutation(kind: .bitFlip, offset: index, value: nil))
                case .truncate where bytes.count > truncateFloor:
                    bytes.removeLast(1 + rng.below(bytes.count - truncateFloor))
                    applied.append(Mutation(kind: .truncate, offset: nil, value: nil))
                default:
                    let extra = 1 + rng.below(maxExtend)
                    for _ in 0 ..< extra { bytes.append(rng.byte()) }
                    applied.append(Mutation(kind: .extend, offset: nil, value: nil))
            }
        }
        return applied
    }

    private func pickIndex(_ count: Int, _ rng: inout SeededRNG) -> Int {
        guard let region, !region.isEmpty else {
            return rng.below(count)
        }
        let lower = max(0, region.lowerBound)
        let upper = min(count, region.upperBound)
        guard upper > lower else {
            return rng.below(count)
        }
        return lower + rng.below(upper - lower)
    }
}

/// The env var that turns on per-iteration repro tracing when a suite does not pass its own.
public let defaultFuzzTraceEnv = "HTTP_FUZZ_TRACE"

/// Byte-mutation fuzz driver: mutate a fresh copy of `corpus()` each iteration, then `exercise` it.
///
/// The PASS condition is process survival: a typed error or `nil` result inside `exercise` is
/// expected-and-fine (the closure swallows its own typed errors), and only a trap fails the run by
/// aborting it. When `traceEnv` is set, each iteration's mutation list prints *before* it runs, so a
/// crashing run's last line is the precise repro.
@discardableResult
public func fuzzNeverTraps(
    seed: Seed,
    iterations: Int,
    edits: ClosedRange<Int> = 1 ... 8,
    mutator: ByteMutator = ByteMutator(),
    traceEnv: String = defaultFuzzTraceEnv,
    corpus: () -> [UInt8],
    exercise: (_ mutated: [UInt8]) -> Void
) -> FuzzReport {
    let trace = ProcessInfo.processInfo.environment[traceEnv] != nil
    let base = corpus()
    var rng = SeededRNG(seed: seed)
    var totalEdits = 0
    for iteration in 0 ..< iterations {
        var blob = base
        let count = rng.int(in: edits)
        let applied = mutator.apply(count, to: &blob, using: &rng)
        totalEdits += applied.count
        if trace {
            let list = applied.map(\.description).joined(separator: ",")
            print("FUZZ i=\(iteration) seed=0x\(String(seed.rawValue, radix: 16)) muts=[\(list)]")
        }
        exercise(blob)
    }
    return FuzzReport(iterations: iterations, totalEdits: totalEdits)
}
