//
//  FileRegionStreamer.swift
//  HTTPServer
//
//  The shared copying file-region pump behind ``ResponseBodyWriter/writeFile(_:)`` (G5): `pread(2)`s the
//  region from the ``FileRegion``'s already-verified descriptor in bounded 64 KiB chunks and pushes each
//  through the writer — the framing-agnostic path every engine can use (h1 chunked, h2 DATA, h3), and the
//  fallback when a transport has no `sendfile(2)`. `pread`, never `read`, so the descriptor's own file
//  offset is never disturbed for a concurrent reader of the same open file.
//
//  Fails closed on a short file: the response head (incl. `Content-Length`) is already committed by the
//  time a body streams, so under-delivering silently would desync the connection (audit F1) — the stream
//  errors instead and the connection closes.
//
//  Standards: pread() per POSIX.1-2017 (IEEE Std 1003.1-2017).
//

/// Streams a ``FileRegion`` through a ``ResponseBodyWriter`` in bounded chunks (the copying path).
enum FileRegionStreamer {
    /// The chunk size the pump never exceeds, whatever the region's length.
    private static let chunkSize = 64 * 1_024

    /// Why a file region could not be delivered in full.
    enum FileError: Error {
        /// The descriptor could not be read (an I/O failure mid-stream).
        case unreadable
        /// The file ended before the framed length (truncated after the head went out).
        case truncated
    }

    /// Streams `region` to `writer` in 64 KiB chunks, failing closed if the file runs short.
    static func stream(_ region: FileRegion, to writer: any ResponseBodyWriter) async throws {
        guard region.length > 0 else {
            return
        }
        var remaining = region.length
        var cursor = region.offset
        var chunk = [UInt8](repeating: 0, count: min(Self.chunkSize, region.length))
        while remaining > 0 {
            let wanted = min(chunk.count, remaining)
            let count = chunk.withUnsafeMutableBytes { buffer in
                POSIXFile.read(
                    region.descriptor, into: buffer, start: 0, count: wanted, at: cursor
                )
            }
            guard count > 0 else {
                // 0 is EOF before the advertised length; -1 an I/O failure. Never stop silently short.
                throw count == 0 ? FileError.truncated : FileError.unreadable
            }
            try await writer.write(Array(chunk[..<count]))
            cursor += count
            remaining -= count
        }
    }
}
