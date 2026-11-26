//
//  ZstdError.swift
//  HTTPZstd
//
//  The typed failures of the Zstandard codec (RFC 8878). Decoding faces untrusted input, so every malformed or
//  over-limit frame surfaces as one of these rather than a trap.
//

/// A Zstandard encoding or decoding failure.
public enum ZstdError: Error, Equatable, Sendable {
    /// The input is not a Zstandard frame, or it is malformed (bad header, corrupt block, wrong checksum).
    case corrupt
    /// The input ends inside a frame.
    case truncated
    /// The decoded content would exceed the caller's limit.
    case outputLimitExceeded
    /// A frame's window exceeds what the decoder accepts for the caller's limit (RFC 8878 §3.1.1.1.2).
    case windowTooLarge
    /// The compression level is outside ``Zstd/levels``.
    case invalidLevel(Int)
    /// An allocation failed.
    case outOfMemory
    /// The stream was used after ``ZstdCompressionStream/finish()``.
    case streamFinished

    /// Maps a negative `CHTTPZSTD_ERROR_*` status.
    init(status: Int) {
        switch status {
            case -2:
                self = .windowTooLarge
            case -3:
                self = .outOfMemory
            default:
                self = .corrupt
        }
    }
}
