//
//  Inflator+Pump.swift
//  HTTPDeflate
//
//  The `[UInt8]` convenience over ``Inflator/run(input:from:into:)`` for callers that hold byte
//  arrays (the WebSocket permessage-deflate codec): inflates through a reused 16 KiB chunk with a
//  hard output cap — the CWE-409 decompression-bomb bound enforced *during* the pump, never after —
//  so no unsafe construction leaks into the caller's target.
//

extension Inflator {
    /// Inflates all of `input`, appending to `output`, refusing to grow it past `limit`.
    ///
    /// - Parameters:
    ///   - input: Coded octets (a whole message segment, or any prefix — the machine suspends).
    ///   - output: The array inflated octets are appended to.
    ///   - limit: The hard cap on `output`'s total count (CWE-409). Exceeding it stops the pump
    ///     with ``CodecProgress/needsOutput`` and appends nothing beyond the cap.
    /// - Returns: ``CodecProgress/needsInput`` (input consumed, stream continues),
    ///   ``CodecProgress/finished`` (BFINAL block completed), or ``CodecProgress/needsOutput``
    ///   (the cap was hit with output still pending — the caller fails closed).
    /// - Throws: ``InflateError`` on any malformed shape.
    public mutating func pump(
        _ input: [UInt8], appendingTo output: inout [UInt8], limit: Int
    ) throws(InflateError) -> CodecProgress {
        var index = 0
        var chunk = [UInt8](repeating: 0, count: min(16_384, max(1, limit)))
        while true {
            var progress = CodecProgress.needsInput
            var failure: InflateError?
            let written = SpanBridge.withSpan(of: input) { inputSpan in
                SpanBridge.withOutputSpan(of: &chunk) { span in
                    do throws(InflateError) {
                        progress = try run(input: inputSpan, from: &index, into: &span)
                    }
                    catch {
                        failure = error
                    }
                }
            }
            if let failure {
                throw failure
            }
            guard output.count + written <= limit else {
                return .needsOutput  // the CWE-409 cap — fail closed, never a partial overrun
            }
            output.append(contentsOf: chunk[0 ..< written])
            if progress != .needsOutput {
                return progress
            }
        }
    }
}
