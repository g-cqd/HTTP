//
//  CRC32+Span.swift
//  HTTPDeflate
//
//  The one bridge between this module's `Span`-shaped byte flow and HTTPCore's CRC-32 (the gzip
//  integrity checksum, RFC 1952 §8). The containers fold spans as octets stream past; the fold
//  itself is HTTPCore's hardware/SWAR-dispatched kernel. This is one of the module's few `unsafe`
//  annotations: the span's bounds are the buffer's bounds by construction, and the pointer never
//  escapes the closure.
//

internal import HTTPCore

extension CRC32.Running {
    /// Folds a borrowed span through the accelerated contiguous path (RFC 1952 §8).
    mutating func update(bytes: Span<UInt8>) {
        var running = self
        // SAFETY: `withUnsafeBufferPointer` exposes exactly the span's own initialized bounds, and
        // the pointer is consumed inside the closure by a length-checked C kernel.
        bytes.withUnsafeBufferPointer { buffer in
            unsafe running.update(buffer)
        }
        self = running
    }
}
