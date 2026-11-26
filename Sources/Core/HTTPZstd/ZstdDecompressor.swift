//
//  ZstdDecompressor.swift
//  HTTPZstd
//
//  Owns one `chttpzstd_dctx` with a window limit, and decodes a whole input under an output limit (RFC 8878): the
//  buffer is sized from the declared content size when there is one, grows geometrically when there is not, and
//  never past the limit — one byte of headroom tells "exactly at the limit" from "over it".
//

internal import CHTTPZstd

/// One libzstd decompression context.
///
/// Used by one owner at a time (see ``ZstdCompressor``).
final class ZstdDecompressor: @unchecked Sendable {
    let windowLogMax: Int
    /// The context's address.
    ///
    /// Kept as an integer so the class stores no unsafe type (SE-0458); every C call rebuilds the pointer from it.
    private let handle: UInt

    init(windowLogMax: Int) throws(ZstdError) {
        guard let context = unsafe chttpzstd_dctx_create(UInt32(windowLogMax)) else {
            throw .outOfMemory
        }
        self.windowLogMax = windowLogMax
        handle = UInt(bitPattern: Int(bitPattern: context))
    }

    deinit {
        unsafe chttpzstd_dctx_free(OpaquePointer(bitPattern: handle))
    }

    /// Forgets any frame in progress.
    func reset() {
        _ = unsafe chttpzstd_dctx_reset(OpaquePointer(bitPattern: handle))
    }

    /// Decodes every frame of `input` (skippable frames included) into at most `limit` bytes.
    func decompress(_ input: [UInt8], declared: Int?, limit: Int) throws(ZstdError) -> [UInt8] {
        let ceiling = limit == Int.max ? limit : limit + 1
        var capacity = min(ceiling, declared.map { $0 + 1 } ?? max(input.count * 4, 65_536))
        var output = [UInt8](repeating: 0, count: capacity)
        var consumed = 0
        var produced = 0
        while true {
            let before = (consumed, produced)
            let status = input.withUnsafeBufferPointer { source in
                output.withUnsafeMutableBufferPointer { destination in
                    unsafe chttpzstd_decompress_stream(
                        OpaquePointer(bitPattern: handle),
                        source.baseAddress,
                        source.count,
                        &consumed,
                        destination.baseAddress,
                        destination.count,
                        &produced
                    )
                }
            }
            guard status >= 0 else { throw ZstdError(status: status) }
            guard produced <= limit else { throw .outputLimitExceeded }
            if status == 0, consumed == input.count { break }
            if produced == capacity {
                guard capacity < ceiling else { throw .outputLimitExceeded }
                capacity = capacity > ceiling / 2 ? ceiling : capacity * 2
                output.append(contentsOf: repeatElement(0, count: capacity - output.count))
            }
            else if consumed == input.count {
                throw .truncated
            }
            else if before == (consumed, produced) {
                throw .corrupt  // neither input taken nor output made: never spin
            }
        }
        output.removeLast(output.count - produced)
        return output
    }
}
