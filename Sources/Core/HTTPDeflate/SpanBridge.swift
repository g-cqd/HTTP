//
//  SpanBridge.swift
//  HTTPDeflate
//
//  The module's `[UInt8]` ⇄ `Span`/`OutputSpan` seam — the ONLY place (with CRC32+Span.swift) an
//  `unsafe` annotation appears. The core pumps speak spans; consumers (the WebSocket codec, the
//  content-coding middleware) speak byte arrays, and concentrating the bridge here keeps every
//  consumer target free of new unsafe sites. `Array.span` needs a newer OS than this package's
//  floor, hence the pointer-mediated construction; the spans never outlive their closures, which
//  the `~Escapable` types themselves enforce.
//

/// The `[UInt8]` ⇄ span bridging helpers (the module's concentrated `unsafe` seam).
enum SpanBridge {
    /// Runs `body` over `bytes` viewed as a borrowed `Span`.
    static func withSpan<R>(of bytes: [UInt8], _ body: (Span<UInt8>) -> R) -> R {
        // SAFETY: the buffer pointer is valid for the closure's duration and the span it seeds is
        // `~Escapable`, so it cannot outlive that borrow.
        bytes.withUnsafeBufferPointer { unsafe body($0.span) }
    }

    /// Runs `body` over an `OutputSpan` covering the whole buffer.
    ///
    /// - Returns: The number of octets the body initialized.
    static func withOutputSpan(
        of buffer: inout [UInt8], _ body: (inout OutputSpan<UInt8>) -> Void
    ) -> Int {
        // SAFETY: the span covers exactly the buffer's own storage (starting empty), is consumed
        // by `finalize` inside the closure, and `~Escapable` keeps it from outliving the borrow.
        buffer.withUnsafeMutableBufferPointer { raw in
            var span = unsafe OutputSpan<UInt8>(buffer: raw, initializedCount: 0)
            body(&span)
            return unsafe span.finalize(for: raw)
        }
    }
}
