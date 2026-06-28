//
//  HTTPFieldName.swift
//  HTTPCore
//
//  RFC 9110 §5.1 — Field Names (and the lower-case requirement of RFC 9113 §8.2 / RFC 9114 §4.2).
//

/// The name of an HTTP field (RFC 9110 §5.1).
///
/// A field name is a `token` (RFC 9110 §5.6.2) compared **case-insensitively** over ASCII. Every
/// name carries a ``canonicalName`` (ASCII-lower-cased) — the form used for comparison and required
/// on the HTTP/2 and HTTP/3 wire — and preserves its original spelling via ``rawName``.
///
/// The original spelling is stored **without heap allocation** when it is known at compile time: the
/// registered constants pass a `StaticString`. Names parsed from the wire at runtime are stored as
/// `String`. Equality and hashing use the canonical form, so `"Content-Type"` and `"content-type"`
/// are equal and collide in a `Set`/`Dictionary`.
public struct HTTPFieldName: Sendable, Hashable {
    /// Backing storage for the original field-name spelling.
    enum RawName: Sendable {
        /// A compile-time name (a registered constant) — stored without heap allocation.
        case literal(StaticString)
        /// A name parsed at runtime.
        case parsed(String)
    }

    let storage: RawName

    /// The ASCII-lower-cased name (e.g. `"content-type"`) — the HTTP/2 / HTTP/3 wire form and the
    /// key used for case-insensitive comparison.
    public let canonicalName: String

    /// The field name in its original spelling (e.g. `"Content-Type"`).
    ///
    /// Materializes a `String` for the registered-constant (`StaticString`) case; prefer
    /// ``appendRawNameUTF8(to:)`` on the response hot path, which avoids that allocation.
    public var rawName: String {
        switch storage {
            case .literal(let name):
                name.description
            case .parsed(let name):
                name
        }
    }

    /// Appends the original-spelling name as UTF-8 bytes to `output`.
    ///
    /// Zero-allocation for the registered-constant case — `StaticString.withUTF8Buffer` exposes the
    /// literal's bytes directly, so the response serializer no longer builds a throwaway `String` per
    /// header (it ran once for every registered name — Content-Type, Server, Date, … — on every
    /// response).
    public func appendRawNameUTF8(to output: inout [UInt8]) {
        switch storage {
            case .literal(let name):
                name.withUTF8Buffer { output.append(contentsOf: $0) }
            case .parsed(let name):
                output.append(contentsOf: name.utf8)
        }
    }

    /// Creates a field name from a runtime token, returning `nil` if it is not a valid `token`.
    public init?(_ name: String) {
        guard FieldValidation.isToken(name.utf8) else {
            return nil
        }
        self.storage = .parsed(name)
        // h2/h3 field names arrive lower-case, so reuse the input when possible to avoid allocating.
        if name.utf8.contains(where: { (0x41 ... 0x5A).contains($0) }) {
            self.canonicalName = Self.asciiLowercased(name.utf8)
        }
        else {
            self.canonicalName = name
        }
    }

    /// Creates a field name by validating raw bytes (e.g. a parser's borrowed buffer), returning
    /// `nil` if they are not a valid `token`.
    ///
    /// This **concrete, non-generic** overload is the parse hot path: the HTTP/1 header parser already
    /// holds an `UnsafeRawBufferPointer` (from `RawSpan.withUnsafeBytes`), so binding it here avoids the
    /// runtime generic-metadata instantiation a `some Collection` entry point pays *per header field,
    /// per request* across the HTTP1→HTTPCore module boundary (audit: tail-latency variance — the
    /// `_swift_getGenericMetadata` cost the profiler flagged in `parseFieldLine`). The nested
    /// `isToken` / `String(decoding:)` / `asciiLowercased` then see a concrete type and specialize too.
    ///
    /// Validates **before** allocating, so a hostile or malformed name costs no heap. The original
    /// spelling is materialized once; the canonical form reuses it when the bytes are already
    /// lower-case (the h2/h3 hot path), else folds in a single allocation.
    public init?(validating bytes: UnsafeRawBufferPointer) {
        guard FieldValidation.isToken(bytes) else {
            return nil
        }
        let raw = String(decoding: bytes, as: Unicode.UTF8.self)
        self.storage = .parsed(raw)
        if bytes.contains(where: { (0x41 ... 0x5A).contains($0) }) {
            self.canonicalName = Self.asciiLowercased(bytes)
        }
        else {
            self.canonicalName = raw
        }
    }

    /// Creates a field name from any byte collection, returning `nil` if it is not a valid `token`.
    ///
    /// A convenience over the concrete ``init?(validating:)-(UnsafeRawBufferPointer)`` for non-buffer
    /// callers (HPACK/QPACK, `[UInt8]`): contiguous storage (`Array`, `ArraySlice`, buffers) is routed
    /// to the concrete path with **no copy**; only a genuinely non-contiguous collection pays a one-time
    /// gather. The cross-module hot path stays on the concrete entry, so no per-field generic metadata
    /// is instantiated.
    public init?(validating bytes: some Collection<UInt8>) {
        // Fast path: contiguous storage (`Array`, `ArraySlice`, buffers) routes to the concrete,
        // fully-specialized initializer with no copy.
        if let validated = bytes.withContiguousStorageIfAvailable({
            Self(validating: UnsafeRawBufferPointer($0))
        }) {
            guard let validated else {
                return nil
            }
            self = validated
            return
        }
        // Rare non-contiguous fallback: validate and materialize **straight off the collection** — no
        // `Array` copy. `isToken` / `String(decoding:)` / `asciiLowercased` each consume the bytes in
        // place, so a non-contiguous `Collection` costs no extra allocation either.
        guard FieldValidation.isToken(bytes) else {
            return nil
        }
        let raw = String(decoding: bytes, as: Unicode.UTF8.self)
        self.storage = .parsed(raw)
        if bytes.contains(where: { (0x41 ... 0x5A).contains($0) }) {
            self.canonicalName = Self.asciiLowercased(bytes)
        }
        else {
            self.canonicalName = raw
        }
    }

    /// Creates a name from a compile-time token already known to be valid (the registered
    /// constants), storing the original spelling as a `StaticString` with no heap allocation.
    init(unchecked name: StaticString) {
        self.storage = .literal(name)
        self.canonicalName = name.withUTF8Buffer { Self.asciiLowercased($0) }
    }

    /// ASCII-lower-cases a validated token's bytes (A–Z → a–z) into a `String`.
    ///
    /// Names are validated ASCII tokens, so an ASCII-only fold is exact and avoids Unicode/locale
    /// case-folding (RFC 9110 §5.1 compares field names case-insensitively). The fold is written
    /// straight into the `String`'s storage in a **single allocation**, instead of building an
    /// intermediate `[UInt8]` (via `map`) and copying it again through `String(decoding:)`.
    static func asciiLowercased(_ utf8: some Collection<UInt8>) -> String {
        String(unsafeUninitializedCapacity: utf8.count) { destination in
            var index = 0
            for byte in utf8 {
                destination[index] = byte >= 0x41 && byte <= 0x5A ? byte &+ 0x20 : byte
                index &+= 1
            }
            return index
        }
    }

    /// Two field names are equal iff their canonical (ASCII-lower-cased) forms match.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.canonicalName == rhs.canonicalName
    }

    /// Hashes the canonical (ASCII-lower-cased) form so equal names share a hash bucket.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(canonicalName)
    }
}
