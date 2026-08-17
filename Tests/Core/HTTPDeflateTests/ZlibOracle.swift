//
//  ZlibOracle.swift
//  HTTPDeflateTests
//
//  The system zlib as a differential oracle, reached through the two shims HTTPDeflate exists to
//  replace (`CZlibCoding` one-shots, `CWSDeflate` sync-flushed raw streams). The house pattern:
//  prove equivalence against the incumbent in one tree, then delete the incumbent — this file and
//  the shims leave together in the replacement sweep.
//

internal import CWSDeflate
internal import CZlibCoding

/// `[UInt8]`-shaped wrappers over the zlib shims, for differential assertions.
enum ZlibOracle {
    /// One-shot gzip compress at `level` (0…9), or nil on a zlib failure.
    static func gzipCompress(_ input: [UInt8], level: Int32) -> [UInt8]? {
        let capacity = czlib_compress_bound(input.count)
        var destination = [UInt8](repeating: 0, count: max(capacity, 64))
        let written = input.withUnsafeBufferPointer { source in
            destination.withUnsafeMutableBufferPointer { output -> Int in
                guard let base = output.baseAddress else {
                    return 0
                }
                return czlib_gzip_compress(
                    base, output.count, source.baseAddress, source.count, level
                )
            }
        }
        guard written > 0 else {
            return nil
        }
        destination.removeLast(destination.count - written)
        return destination
    }

    /// One-shot gzip/zlib inflate (header auto-detect) into `capacity` octets, or nil.
    static func inflate(_ input: [UInt8], capacity: Int) -> [UInt8]? {
        oneShot(input, capacity: capacity, raw: false)
    }

    /// One-shot raw-DEFLATE inflate into `capacity` octets, or nil.
    static func inflateRaw(_ input: [UInt8], capacity: Int) -> [UInt8]? {
        oneShot(input, capacity: capacity, raw: true)
    }

    private static func oneShot(_ input: [UInt8], capacity: Int, raw: Bool) -> [UInt8]? {
        var destination = [UInt8](repeating: 0, count: max(capacity, 1))
        let written = input.withUnsafeBufferPointer { source in
            destination.withUnsafeMutableBufferPointer { output -> Int in
                guard let base = output.baseAddress, let sourceBase = source.baseAddress else {
                    return 0
                }
                return raw
                    ? czlib_inflate_raw(base, output.count, sourceBase, source.count)
                    : czlib_inflate(base, output.count, sourceBase, source.count)
            }
        }
        guard written > 0 else {
            // zlib's one-shot conflates "decoded to empty" with failure; the fixtures avoid it.
            return nil
        }
        return Array(destination[0 ..< written])
    }

    /// A persistent raw-DEFLATE compressor flushing every message with `Z_SYNC_FLUSH` (RFC 7692).
    final class SyncDeflater {
        private let stream: OpaquePointer

        init?() {
            guard let stream = cws_deflate_new(15) else {
                return nil
            }
            self.stream = stream
        }

        deinit {
            cws_deflate_free(stream)
        }

        /// Compresses one message, returning the full sync-flushed octets (tail included), or nil.
        func compress(_ message: [UInt8]) -> [UInt8]? {
            var output: [UInt8] = []
            var window = [UInt8](repeating: 0, count: 16_384)
            let ok = message.withUnsafeBufferPointer { source -> Bool in
                cws_deflate_input(stream, source.baseAddress, source.count)
                while true {
                    var done: Int32 = 0
                    let written = window.withUnsafeMutableBufferPointer {
                        cws_deflate_run(stream, $0.baseAddress, $0.count, &done)
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
    }

    /// A persistent raw-DEFLATE decompressor (RFC 7692 receive side).
    final class SyncInflater {
        private let stream: OpaquePointer

        init?() {
            guard let stream = cws_inflate_new(15) else {
                return nil
            }
            self.stream = stream
        }

        deinit {
            cws_inflate_free(stream)
        }

        /// Inflates one sync-flushed segment, or nil on a zlib error.
        func inflate(_ segment: [UInt8], capacity: Int = 1 << 22) -> [UInt8]? {
            var output: [UInt8] = []
            var window = [UInt8](repeating: 0, count: 16_384)
            let ok = segment.withUnsafeBufferPointer { source -> Bool in
                cws_inflate_input(stream, source.baseAddress, source.count)
                while true {
                    var done: Int32 = 0
                    let written = window.withUnsafeMutableBufferPointer {
                        cws_inflate_run(stream, $0.baseAddress, $0.count, &done)
                    }
                    if written < 0 {
                        return false
                    }
                    if written > 0 {
                        guard output.count + written <= capacity else {
                            return false
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
}
