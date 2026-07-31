//
//  MultipartLimits.swift
//  HTTPCore
//
//  RFC 7578 — the resource bounds a `multipart/form-data` body needs beyond `HTTPLimits/maxBodySize`.
//  A body cap bounds the WIRE bytes. It says nothing about how much structure those bytes force the
//  parser to build, and every amplification below fits comfortably under any body cap:
//
//    • part count — a part costs only `\r\n--B\r\nContent-Disposition: form-data; name="a"\r\n\r\n`,
//      so a megabyte buys tens of thousands of owned `Part` values, each with its own `String`s and
//      its own array (CWE-770, allocation of resources without limits);
//    • per-part header bytes — one part whose header section is the entire body forces a header
//      allocation of that size and a line scan over it (CWE-400, uncontrolled resource consumption);
//    • aggregate retained bytes — the parsed form holds a SECOND copy of nearly every payload byte,
//      so peak memory is roughly twice the body, which no body cap expresses.
//
//  Each bound is separate on purpose: raising the tolerance for large uploads must not silently raise
//  the tolerance for many parts, and vice versa.
//

/// Independent resource bounds enforced while parsing a `multipart/form-data` body (RFC 7578).
///
/// A body that breaches any of them is rejected outright — `MultipartFormData.parse` returns `nil` and
/// `MultipartFormDecoder` throws `BodyDecodingError/malformed`. Failing closed is the point: a partial
/// form parsed from a body the server refused to bound is worse than no form.
public struct MultipartLimits: Sendable, Equatable {
    /// Maximum number of parts a body may contain (CWE-770).
    ///
    /// Counts parts *encountered*, not parts retained, so a flood of parts the parser would otherwise
    /// skip — no `Content-Disposition`, no `name` — is bounded by the same number.
    public var maxParts: Int

    /// Maximum bytes in one part's header section, excluding its terminating blank line (CWE-400).
    public var maxPartHeaderBytes: Int

    /// Maximum total bytes retained across every part the parse returns (CWE-770).
    ///
    /// Counts each retained part's payload plus its header-derived `name`, `filename` and
    /// `contentType`, i.e. the memory the returned value actually holds — not the wire bytes consumed
    /// reaching it.
    public var maxRetainedBytes: Int

    /// The limits applied when a caller names none.
    ///
    /// Sized for the in-memory form APIs that reach this parser rather than for bulk file transfer:
    /// 1,024 parts covers any realistic browser form, 16 KiB of part headers matches
    /// `HTTPLimits/maxFieldSize`, and 32 MiB of retained payload sits above `HTTPLimits/hardened`'s
    /// 16 MiB body cap so a hardened deployment never trips it by accident.
    public static let `default` = Self()

    /// Creates the limits, defaulting each bound to its ``default`` value.
    ///
    /// A non-positive bound is honoured literally — it admits nothing — rather than being reinterpreted
    /// as "unlimited", so a misconfiguration fails closed and is noticed.
    public init(
        maxParts: Int = 1_024,
        maxPartHeaderBytes: Int = 16 * 1_024,
        maxRetainedBytes: Int = 32 * 1_024 * 1_024
    ) {
        self.maxParts = maxParts
        self.maxPartHeaderBytes = maxPartHeaderBytes
        self.maxRetainedBytes = maxRetainedBytes
    }
}
