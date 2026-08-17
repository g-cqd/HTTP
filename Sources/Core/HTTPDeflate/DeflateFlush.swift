//
//  DeflateFlush.swift
//  HTTPDeflate
//
//  The compressor's flush request — the RFC 1951 framing decisions a caller can force. `sync` is the
//  RFC 7692 §7.2.1 message boundary (zlib's `Z_SYNC_FLUSH`): terminate the current block and emit the
//  empty stored block whose `00 00 FF FF` tail lands the stream on a byte boundary. `finish` seals
//  the stream with a BFINAL block. `none` promises nothing — which is exactly what makes the output a
//  function of the input octets alone, independent of chunking (the streamed/buffered byte-identity
//  the content codings pin).
//

/// How much framing the compressor must complete before reporting ``CodecProgress/needsInput``.
public enum DeflateFlush: Sendable, Equatable {
    /// No boundary: buffer freely, emit blocks only when internally full. Output depends only on the
    /// input octets, never on how they were chunked.
    case none
    /// Terminate the current block and append the empty stored block ending `00 00 FF FF`, leaving
    /// the stream byte-aligned (zlib `Z_SYNC_FLUSH`; RFC 7692 §7.2.1).
    case sync
    /// Compress everything buffered and seal the stream with a BFINAL block (RFC 1951 §3.2.3).
    case finish
}
