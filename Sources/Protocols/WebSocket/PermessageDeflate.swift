//
//  PermessageDeflate.swift
//  WebSocket
//
//  RFC 7692 — per-connection permessage-deflate over the in-house HTTPDeflate codec (system zlib
//  left this path with the CWSDeflate shim). A message compresses as raw DEFLATE completed with a
//  sync flush, whose empty `00 00 FF FF` stored block §7.2.1 strips; decompression re-appends it
//  and inflates (§7.2.2). The compressor/decompressor keep their LZ77 windows across messages for
//  context-takeover; a `no_context_takeover` direction resets its stream per message. The inflated
//  size is hard-capped against a decompression bomb (CWE-409) — the codec enforces the cap during
//  the pump, so an oversized message never materializes.
//
//  Stateful (it owns the two codec windows), so a final class: one instance per connection, driven
//  on that connection's single task — never shared across tasks.
//

internal import HTTPDeflate

/// A per-connection RFC 7692 permessage-deflate codec over HTTPDeflate (raw DEFLATE + sync flush).
final class PermessageDeflate {
    /// The empty-uncompressed DEFLATE block a sync flush ends with — stripped on compress (§7.2.1)
    /// and re-appended on decompress (§7.2.2).
    static let syncTail: [UInt8] = [0x00, 0x00, 0xFF, 0xFF]

    private var compressor: Deflator
    private var decompressor: Inflator
    private let serverNoContextTakeover: Bool
    private let clientNoContextTakeover: Bool

    /// Creates a codec for the negotiated `parameters`.
    ///
    /// Failable for callers' sake only — the in-house codec has no initialization failure mode
    /// (the zlib shim it replaced could fail on OOM).
    init?(parameters: PermessageDeflateParameters) {
        compressor = Deflator()
        decompressor = Inflator()
        serverNoContextTakeover = parameters.serverNoContextTakeover
        clientNoContextTakeover = parameters.clientNoContextTakeover
    }

    deinit {
        // The codec state is plain Swift storage; ARC releases it here (the zlib shim this
        // replaced had C allocations to free).
    }

    /// Compresses one outbound message to bit-exact RFC 7692 §7.2.1 framing.
    ///
    /// Deflates with a sync flush then strips the trailing `00 00 FF FF`, resetting the compressor
    /// first under `server_no_context_takeover`. Returns nil only if the codec produced an
    /// impossible shape (defensive); the caller then sends the message uncompressed.
    func compress(_ message: [UInt8]) -> [UInt8]? {
        if serverNoContextTakeover {
            compressor.reset()
        }
        var output: [UInt8] = []
        let progress = compressor.pump(message, appendingTo: &output, flush: .sync)
        guard progress == .needsInput, output.count >= Self.syncTail.count else {
            return nil
        }
        return Array(output.dropLast(Self.syncTail.count))
    }

    /// Decompresses one inbound message per RFC 7692 §7.2.2, bounding the output to `maxSize`.
    ///
    /// Appends the `00 00 FF FF` boundary and inflates, resetting the decompressor first under
    /// `client_no_context_takeover`. Returns nil on a malformed stream or output exceeding
    /// `maxSize` — the CWE-409 decompression-bomb cap, enforced during the pump.
    func decompress(_ message: [UInt8], maxSize: Int) -> [UInt8]? {
        guard maxSize > 0 else {
            return nil
        }
        if clientNoContextTakeover {
            decompressor.reset()
        }
        var output: [UInt8] = []
        do {
            let progress = try decompressor.pump(
                message + Self.syncTail, appendingTo: &output, limit: maxSize
            )
            guard progress != .needsOutput else {
                return nil  // the bomb cap fired — fail closed
            }
        }
        catch {
            return nil  // malformed DEFLATE — the connection layer fails the message
        }
        return output
    }
}
