//
//  CodecProgress.swift
//  HTTPDeflate
//
//  The tri-state a sans-I/O pump reports: the shared "why did `run` return" vocabulary of the
//  DEFLATE (RFC 1951) compressor and decompressor and their gzip/zlib containers. Mirrors the shape
//  of zlib's `avail_in == 0` / `avail_out == 0` / `Z_STREAM_END` outcomes as one typed value.
//

/// Why a codec's `run` returned: it wants bytes, it wants room, or the stream is complete.
public enum CodecProgress: Sendable, Equatable {
    /// Every input octet was consumed (and every pending output octet drained); feed more input —
    /// or, for a compressor, request a flush.
    case needsInput
    /// The output ran out of free capacity with coded octets still pending; drain and call again.
    case needsOutput
    /// The stream is structurally complete (the DEFLATE final block — and, for a container, its
    /// trailer — has been fully processed). Further input belongs to the caller, not the stream.
    case finished
}
