//
//  GzipDeflator+Pump.swift
//  HTTPDeflate
//
//  The `[UInt8]` convenience over ``GzipDeflator/run(input:from:into:flush:)`` for the streaming
//  content coding (`ContentEncoderStream`'s update/finish shape): consumes the whole chunk,
//  appending through a reused 16 KiB window so no unsafe construction leaks into the caller.
//

extension GzipDeflator {
    /// Compresses all of `input` into the member (completing `flush`), appending to `output`.
    ///
    /// - Parameters:
    ///   - input: The plain octets to compress, consumed entirely.
    ///   - output: The array the member's octets are appended to.
    ///   - flush: The boundary to complete; ``DeflateFlush/finish`` seals the member.
    /// - Returns: ``CodecProgress/needsInput`` (caught up), or ``CodecProgress/finished`` once the
    ///   trailer has been fully appended.
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
