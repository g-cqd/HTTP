//
//  PermessageDeflate.swift
//  WebSocket
//
//  RFC 7692 — per-connection permessage-deflate, bit-exact, over the `CWSDeflate` zlib shim. zlib is the
//  only DEFLATE backend exposing `Z_SYNC_FLUSH` (Apple's Compression cannot, proven by probe), so a
//  message compresses as raw DEFLATE flushed with the empty `00 00 FF FF` block, which §7.2.1 strips;
//  decompression re-appends it and inflates (§7.2.2). The compressor/decompressor streams persist their
//  LZ77 history across messages for context-takeover; a `no_context_takeover` direction resets its
//  stream per message. The inflated size is hard-capped against a decompression bomb (CWE-409).
//
//  Stateful (it owns two `z_stream`s), so a final class with a deinit that frees them. One instance per
//  connection, driven on that connection's single task — never shared across tasks.
//

internal import CWSDeflate

/// A per-connection RFC 7692 permessage-deflate codec backed by zlib (raw DEFLATE + `Z_SYNC_FLUSH`).
final class PermessageDeflate {
    /// The empty-uncompressed DEFLATE block a sync flush ends with — stripped on compress (§7.2.1) and
    /// re-appended on decompress (§7.2.2).
    static let syncTail: [UInt8] = [0x00, 0x00, 0xFF, 0xFF]

    /// The full 15-bit DEFLATE window (RFC 7692 §7.1.2; this endpoint does not negotiate a smaller one).
    private static let windowBits: Int32 = 15

    /// The output window size; each `*_run` pass fills at most this, bounding the bomb-cap overshoot.
    private static let chunk = 16 << 10

    private let compressor: OpaquePointer
    private let decompressor: OpaquePointer
    private let serverNoContextTakeover: Bool
    private let clientNoContextTakeover: Bool

    /// Creates a codec for the negotiated `parameters`, or nil if zlib initialization fails (OOM).
    init?(parameters: PermessageDeflateParameters) {
        guard let compressor = cws_deflate_new(Self.windowBits) else {
            return nil
        }
        guard let decompressor = cws_inflate_new(Self.windowBits) else {
            cws_deflate_free(compressor)
            return nil
        }
        self.compressor = compressor
        self.decompressor = decompressor
        self.serverNoContextTakeover = parameters.serverNoContextTakeover
        self.clientNoContextTakeover = parameters.clientNoContextTakeover
    }

    deinit {
        cws_deflate_free(compressor)
        cws_inflate_free(decompressor)
    }

    /// Compresses one outbound message to bit-exact RFC 7692 §7.2.1 framing.
    ///
    /// Deflates with `Z_SYNC_FLUSH` then strips the trailing `00 00 FF FF`, resetting the compressor
    /// first under `server_no_context_takeover`. Returns nil on a zlib stream error; the caller then
    /// sends the message uncompressed.
    func compress(_ message: [UInt8]) -> [UInt8]? {
        if serverNoContextTakeover {
            _ = cws_deflate_reset(compressor)
        }
        guard let output = pumpCompress(message), output.count >= Self.syncTail.count else {
            return nil
        }
        return Array(output.dropLast(Self.syncTail.count))
    }

    /// Decompresses one inbound message per RFC 7692 §7.2.2, bounding the output to `maxSize` (CWE-409).
    ///
    /// Appends the `00 00 FF FF` boundary and inflates, resetting the decompressor first under
    /// `client_no_context_takeover`. Returns nil on a malformed stream or output exceeding `maxSize`.
    func decompress(_ message: [UInt8], maxSize: Int) -> [UInt8]? {
        guard maxSize > 0 else {
            return nil
        }
        if clientNoContextTakeover {
            _ = cws_inflate_reset(decompressor)
        }
        return pumpInflate(message + Self.syncTail, maxSize: maxSize)
    }

    /// Drives the compressor over `message` window by window, accumulating the full sync-flushed output.
    private func pumpCompress(_ message: [UInt8]) -> [UInt8]? {
        var output: [UInt8] = []
        var window = [UInt8](repeating: 0, count: Self.chunk)
        let ok = message.withUnsafeBufferPointer { src -> Bool in
            cws_deflate_input(compressor, src.baseAddress, src.count)
            while true {
                var done: Int32 = 0
                let written = window.withUnsafeMutableBufferPointer {
                    cws_deflate_run(compressor, $0.baseAddress, $0.count, &done)
                }
                if written < 0 {
                    return false
                }
                if written > 0 {
                    output.append(contentsOf: window.prefix(written))
                }
                if done != 0 || written == 0 {
                    return true
                }
            }
        }
        return ok ? output : nil
    }

    /// Drives the decompressor over `input` (message + sync tail), bounding the output to `maxSize`.
    private func pumpInflate(_ input: [UInt8], maxSize: Int) -> [UInt8]? {
        var output: [UInt8] = []
        var window = [UInt8](repeating: 0, count: Self.chunk)
        let ok = input.withUnsafeBufferPointer { src -> Bool in
            cws_inflate_input(decompressor, src.baseAddress, src.count)
            while true {
                var done: Int32 = 0
                let written = window.withUnsafeMutableBufferPointer {
                    cws_inflate_run(decompressor, $0.baseAddress, $0.count, &done)
                }
                if written < 0 {
                    return false
                }
                if written > 0 {
                    guard output.count + written <= maxSize else {
                        return false  // CWE-409 decompression-bomb cap
                    }
                    output.append(contentsOf: window.prefix(written))
                }
                if done != 0 || written == 0 {
                    return true
                }
            }
        }
        return ok ? output : nil
    }
}
