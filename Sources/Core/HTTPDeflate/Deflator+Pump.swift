//
//  Deflator+Pump.swift
//  HTTPDeflate
//
//  The `[UInt8]` convenience over ``Deflator/run(input:from:into:flush:)`` for callers that hold
//  byte arrays (the WebSocket permessage-deflate codec): consumes the whole input, completes any
//  armed flush, and appends through a reused 16 KiB chunk so no unsafe construction leaks into the
//  caller's target.
//

extension Deflator {
    /// Compresses all of `input` (completing `flush`), appending the coded octets to `output`.
    ///
    /// - Parameters:
    ///   - input: The plain octets to compress, consumed entirely.
    ///   - output: The array coded octets are appended to.
    ///   - flush: The boundary to complete before returning.
    /// - Returns: ``CodecProgress/needsInput`` (caught up), or ``CodecProgress/finished`` once a
    ///   `finish` flush sealed the stream.
    @discardableResult
    public mutating func pump(
        _ input: [UInt8], appendingTo output: inout [UInt8], flush: DeflateFlush = .none
    ) -> CodecProgress {
        var index = 0
        var chunk = [UInt8](repeating: 0, count: 16_384)
        while true {
            var progress = CodecProgress.needsInput
            let written = SpanBridge.withSpan(of: input) { inputSpan in
                SpanBridge.withOutputSpan(of: &chunk) { span in
                    progress = run(input: inputSpan, from: &index, into: &span, flush: flush)
                }
            }
            output.append(contentsOf: chunk[0 ..< written])
            if progress != .needsOutput {
                return progress
            }
        }
    }
}
