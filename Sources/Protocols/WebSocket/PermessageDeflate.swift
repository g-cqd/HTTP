//
//  PermessageDeflate.swift
//  WebSocket
//
//  RFC 7692 — per-message DEFLATE, scoped to `no_context_takeover` (§7.1.1.1 / §7.1.1.2): each message
//  is (de)compressed with its own fresh DEFLATE stream, so no LZ77 history carries between messages.
//  Built over Apple's Compression framework (`COMPRESSION_ZLIB` is raw RFC 1951 DEFLATE, no zlib
//  wrapper), which has no `Z_SYNC_FLUSH`: `compression_stream_process` either buffers everything
//  (flags 0 emits nothing until more input) or finalizes (a BFINAL block). So a message is compressed
//  as a *finalized* fresh stream — which IS no_context_takeover — and decompressed per §7.2.2 by
//  appending the `00 00 FF FF` empty-block tail and inflating, with the inflated size hard-capped
//  against a decompression bomb (CWE-409). Context-takeover would need a real `Z_SYNC_FLUSH` (only
//  zlib exposes it) and is out of scope; full RFC 7692 / browser interop is validated under P10.
//

internal import Compression

/// Per-message permessage-deflate over Apple Compression (RFC 7692, `no_context_takeover`).
enum PermessageDeflate {
    /// The empty-uncompressed DEFLATE block (`00 00 FF FF`) a decompressor appends before inflating
    /// (RFC 7692 §7.2.2) — the sync-flush boundary the on-the-wire form omits.
    static let syncTail: [UInt8] = [0x00, 0x00, 0xFF, 0xFF]

    /// The output window size; each `compression_stream_process` pass fills at most this many octets,
    /// so the decode bomb cap overshoots by at most one window before failing closed.
    private static let windowSize = 16 << 10

    /// Compresses one message as an independent finalized raw-DEFLATE stream (`no_context_takeover`).
    ///
    /// Returns nil on a Compression-framework error; the caller then sends the message uncompressed.
    static func compress(_ message: [UInt8]) -> [UInt8]? {
        process(message, operation: COMPRESSION_STREAM_ENCODE, finalize: true, maxOutput: nil)
    }

    /// Decompresses one message (RFC 7692 §7.2.2): append the `00 00 FF FF` tail, inflate, and bound the
    /// output to `maxSize` octets — the CWE-409 decompression-bomb defense.
    ///
    /// Returns nil only when the inflated output would exceed `maxSize` (fail closed — never a partial
    /// message). Note: Apple's Compression decoder is *lenient* on a malformed DEFLATE stream — it
    /// returns best-effort (often empty) output rather than erroring — so a corrupt frame yields a short
    /// or empty message rather than a hard reject here; a compressed *text* message that inflates to
    /// non-UTF-8 is still rejected by the caller's §8.1 screen, and the size cap still bounds a bomb.
    static func decompress(_ message: [UInt8], maxSize: Int) -> [UInt8]? {
        guard maxSize > 0 else {
            return nil
        }
        return process(
            message + syncTail,
            operation: COMPRESSION_STREAM_DECODE,
            finalize: false,
            maxOutput: maxSize
        )
    }

    /// Runs one fresh `compression_stream` over `source` to completion, accumulating its output.
    ///
    /// `finalize` ends an encode stream (BFINAL); a decode stream is not finalized — the appended tail
    /// leaves the inflate stream open, so it stops once input is drained and output stalls. Returns nil
    /// on a process error or when the output would exceed `maxOutput` (the decode bomb cap, CWE-409).
    private static func process(
        _ source: [UInt8],
        operation: compression_stream_operation,
        finalize: Bool,
        maxOutput: Int?
    ) -> [UInt8]? {
        var window = [UInt8](repeating: 0, count: windowSize)
        return window.withUnsafeMutableBufferPointer { out -> [UInt8]? in
            guard let dst = out.baseAddress else {
                return nil
            }
            return source.withUnsafeBufferPointer { src -> [UInt8]? in
                // A valid non-null src pointer is required even for an empty message; the window's base
                // is a zero-length placeholder (`src_size == 0` is never dereferenced) — no force-unwrap.
                var stream = compression_stream(
                    dst_ptr: dst,
                    dst_size: out.count,
                    src_ptr: src.baseAddress ?? UnsafePointer(dst),
                    src_size: src.count,
                    state: nil
                )
                guard
                    compression_stream_init(&stream, operation, COMPRESSION_ZLIB)
                        == COMPRESSION_STATUS_OK
                else { return nil }
                defer { compression_stream_destroy(&stream) }
                // `init` may reset the buffer fields, so (re)point src after it (dst is set per pass).
                stream.src_ptr = src.baseAddress ?? UnsafePointer(dst)
                stream.src_size = src.count
                return drain(
                    &stream, dst: dst, capacity: out.count, finalize: finalize, max: maxOutput
                )
            }
        }
    }

    /// Pumps `stream` window by window into the accumulated output until it ends, stalls, or overflows.
    private static func drain(
        _ stream: inout compression_stream,
        dst: UnsafeMutablePointer<UInt8>,
        capacity: Int,
        finalize: Bool,
        max maxOutput: Int?
    ) -> [UInt8]? {
        let flags = finalize ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0
        var output: [UInt8] = []
        while true {
            stream.dst_ptr = dst
            stream.dst_size = capacity
            let status = compression_stream_process(&stream, flags)
            let produced = capacity - stream.dst_size
            if produced > 0 {
                if let maxOutput, output.count + produced > maxOutput {
                    return nil
                }
                output.append(contentsOf: UnsafeBufferPointer(start: dst, count: produced))
            }
            switch status {
                case COMPRESSION_STATUS_END:
                    return output
                case COMPRESSION_STATUS_OK:
                    // A decode stream has no BFINAL: stop once input is drained and output stalls.
                    if !finalize, stream.src_size == 0, produced == 0 {
                        return output
                    }
                    continue
                default:
                    return nil  // COMPRESSION_STATUS_ERROR
            }
        }
    }
}
