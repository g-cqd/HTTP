//
//  ReceiveScratch.swift
//  HTTPTransport
//
//  The per-connection receive buffer every socket backbone reads into (ADD-P2), sized to what the peer
//  actually sends rather than to the ceiling the caller is willing to accept.
//
//  Audit P1 made the buffer *reused* — one allocation per connection instead of one per read — but it
//  sized that one allocation to `maxLength` on the connection's FIRST read and then held it for the
//  connection's life. The server asks for 16 KiB on every HTTP/1 read, so an 87-octet `GET /` bought a
//  16 KiB resident buffer that stayed resident for as long as the peer kept the keep-alive open, which
//  for a keep-alive server is nearly all of the time. At the default `HTTPLimits.maxConnections` of
//  16,384 that is 256 MiB of scratch nobody is reading from (CWE-400, uncontrolled resource
//  consumption: nothing is leaked, but the ceiling on idle residency is set by the CALLER's willingness
//  to accept a large read rather than by any peer's demonstrated need for one).
//
//  This is the same shape audit CR-F5 removed from the server's own keep-alive read buffer one layer
//  up, and it is resolved the same way: keep the common case small, and let a connection that
//  demonstrably needs the room grow into it.
//
//  Standards: `read(2)` / `recv(2)` per POSIX.1-2017 (IEEE Std 1003.1-2017) may return fewer octets
//  than requested, which is what makes a window smaller than the caller's ceiling legal — a short read
//  is indistinguishable to the caller from a peer that simply sent less. CWE-190 (integer overflow) is
//  why the doubling below reports overflow rather than trapping.
//

/// A per-connection receive buffer whose size follows what the peer sends, not what the caller allows.
///
/// The window starts at ``floorWindow``, doubles after any read that fills it (up to the caller's
/// ceiling), and halves after ``shrinkRun`` consecutive reads that used at most a quarter of it. Two
/// invariants make it a strict improvement on sizing straight to the ceiling:
///
/// - Residency never exceeds `max(floorWindow, largest ceiling ever passed)`, which for every caller in
///   this package is at most what the fixed-ceiling policy held from the first read onward.
/// - Growth is lazy (the doubled window is materialized by the *next* read, so a connection that
///   saturates once and dies never pays for the buffer it earned) while shrink is eager (the octets an
///   idle connection holds are the entire point, and an idle connection never reads again).
///
/// Not `Mutex`-guarded itself: each backbone already owns the lock, because the `read(2)` runs on the
/// event-loop thread while the copy-out runs on the awaiting task.
struct ReceiveScratch {
    /// The window every connection starts at, and the floor a shrink never goes below.
    ///
    /// 2 KiB holds a complete HTTP/1.1 request head — request line, host, user agent, accept set, and a
    /// normal cookie jar — in a single `read(2)`, so the overwhelmingly common connection never grows at
    /// all. Below that, ordinary browser requests would need a second syscall each; above it, the
    /// residency this type exists to remove comes straight back. A connection whose peer really does
    /// send more pays one extra `read(2)` per doubling — at most three to reach the 16 KiB the server
    /// asks for, once, against the ~14 KiB per idle connection that buys.
    static let floorWindow = 2_048

    /// How many consecutive quarter-full reads a connection must make before its window halves.
    ///
    /// The run is what keeps the policy from thrashing: a peer alternating one saturating read with
    /// small ones never triggers a shrink at all, and the worst an adversary can force is one
    /// reallocation of at most the ceiling per eight `read(2)` syscalls it pays for itself — an
    /// amplification factor far below one, so this is not a CWE-400 lever.
    static let shrinkRun = 8

    /// The buffer the last read used — empty until the first read, `window` octets after it.
    private var storage: [UInt8] = []

    /// The adaptive read size, in `floorWindow ... ceiling`.
    private var window = Self.floorWindow

    /// Consecutive reads that used at most a quarter of the window.
    private var smallReads = 0

    /// The octets this scratch currently holds resident — `0` before the first read.
    ///
    /// The residency oracle: allocation *counting* cannot see how large an allocation was, so this is
    /// what the tests and the backbones assert against.
    var residentBytes: Int { storage.count }

    /// The `count` octets the last read produced.
    ///
    /// `count` is always one this scratch returned from ``read(ceiling:_:)``, so it is within the
    /// storage the same read sized.
    func received(_ count: Int) -> ArraySlice<UInt8> {
        storage[..<count]
    }

    /// Reads through `body` into a window of at most `ceiling` octets, adapting the window.
    ///
    /// `body` receives the writable window and returns the octet count it produced; a `body` that
    /// throws (an `EAGAIN` that must re-arm readiness, or a genuine I/O failure) leaves the window
    /// untouched, because a read that never happened says nothing about how much room the peer needs.
    mutating func read(
        ceiling: Int,
        _ body: (UnsafeMutableRawBufferPointer) throws -> Int
    ) rethrows -> Int {
        let size = prepare(ceiling: ceiling)
        let produced = try storage.withUnsafeMutableBytes { raw in
            // SE-0458 (ADR 0009): rebasing a raw buffer is unsafe by import. `size` is
            // `min(window, ceiling)` clamped at zero, and ``prepare(ceiling:)`` has just established
            // `storage.count == window` for any `size > 0`, so the slice is always within the storage
            // this same call sized. The pointer does not escape `body`.
            try unsafe body(UnsafeMutableRawBufferPointer(rebasing: raw[..<size]))
        }
        adapt(produced: produced, size: size, ceiling: ceiling)
        return produced
    }

    /// The window a saturating read earns from `window` against `ceiling`.
    ///
    /// Doubling reports overflow rather than trapping (CWE-190): a ceiling past `Int.max / 2` is not
    /// reachable memory, so the ceiling itself is the answer there.
    static func grown(window: Int, ceiling: Int) -> Int {
        let doubled = window.multipliedReportingOverflow(by: 2)
        guard !doubled.overflow else {
            return ceiling
        }
        return min(doubled.partialValue, ceiling)
    }

    /// Materializes the window if the last read left a different one, and returns the octets to read.
    ///
    /// A zero-length read materializes nothing, so `receive(maxLength: 0)` stays free.
    private mutating func prepare(ceiling: Int) -> Int {
        let size = max(0, min(window, ceiling))
        if size > 0, storage.count != window {
            storage = [UInt8](repeating: 0, count: window)
        }
        return size
    }

    /// Folds one read's outcome into the window.
    private mutating func adapt(produced: Int, size: Int, ceiling: Int) {
        // Only a read against the FULL window can grow it: a read the caller capped (`size < window`)
        // filled everything it was offered without showing the peer had more. It can still shrink the
        // window — a caller that has started asking for small reads genuinely needs less room.
        if produced >= size, size == window {
            smallReads = 0
            window = Self.grown(window: window, ceiling: ceiling)
            return
        }
        // A non-positive count is not a read at all: it is an end of stream, a zero-length ceiling,
        // or — on the TLS backbone, where `body` is `SSL_read` — a `WANT_READ` to be retried once
        // more ciphertext has been pumped in. It says nothing either way about how much room the peer
        // needs, so it is neutral: it neither counts toward a shrink run nor clears one. Clearing
        // would be just as wrong as counting, because the TLS decrypt loop interleaves a retry with
        // every real read, and a run that resets on each retry could never complete.
        guard produced > 0 else {
            return
        }
        guard produced <= size / 4 else {
            smallReads = 0
            return
        }
        smallReads += 1
        guard smallReads >= Self.shrinkRun else {
            return
        }
        smallReads = 0
        shrink()
    }

    /// Halves the window toward the floor and releases the storage the old one held.
    ///
    /// Eager, unlike growth: an idle connection is exactly the one this reclaims from, and it will not
    /// read again to materialize a lazily smaller window.
    private mutating func shrink() {
        let halved = max(window / 2, Self.floorWindow)
        guard halved != window else {
            return
        }
        window = halved
        storage = [UInt8](repeating: 0, count: halved)
    }
}
