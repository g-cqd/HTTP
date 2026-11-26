//
//  ZstdCompressor.swift
//  HTTPZstd
//
//  Owns one `chttpzstd_cctx`: created at a level, reset between frames, freed on deinit. Driving it is the only
//  place compression touches pointers: every buffer is passed with its exact extent, and the C side reports how far
//  it got in each.
//

internal import CHTTPZstd

/// One libzstd compression context (RFC 8878).
///
/// Used by one owner at a time — ``ZstdContextPool`` hands it out and
/// takes it back — which is why it can be `@unchecked Sendable`: it is moved between tasks, never shared.
final class ZstdCompressor: @unchecked Sendable {
    let level: Int
    /// The libzstd context; `context.reset()` abandons a frame in progress.
    let context: ZstdContext

    init(level: Int) throws(ZstdError) {
        guard Zstd.levels.contains(level) else { throw .invalidLevel(level) }
        self.level = level
        context = try .compression(level: level)
    }

    deinit {
        // The compression context is freed with `context`.
    }

    /// Compresses `input`, appending the output to `output`; with `end`, finishes the frame.
    func compress(_ input: [UInt8], end: Bool, into output: inout [UInt8]) throws(ZstdError) {
        var consumed = 0
        var attempt = 0
        while true {
            // First what this input can become; when libzstd has a whole block to flush, a block's worth.
            let bound = chttpzstd_compress_bound(input.count - consumed) + 64
            let room = attempt == 0 ? bound : max(bound, 1 << 17 + 512)
            attempt += 1
            let start = output.count
            output.append(contentsOf: repeatElement(0, count: room))
            var produced = start
            let status = input.withUnsafeBufferPointer { source in
                output.withUnsafeMutableBufferPointer { destination in
                    unsafe chttpzstd_compress_stream(
                        context.pointer,
                        source.baseAddress,
                        source.count,
                        &consumed,
                        destination.baseAddress,
                        destination.count,
                        &produced,
                        end ? 1 : 0
                    )
                }
            }
            output.removeLast(output.count - produced)
            guard status >= 0 else { throw ZstdError(status: status) }
            if status == 0 {
                return
            }
        }
    }
}
