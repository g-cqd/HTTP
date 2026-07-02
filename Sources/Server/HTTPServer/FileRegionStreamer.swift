//
//  FileRegionStreamer.swift
//  HTTPServer
//
//  The shared copying file-region pump behind ``ResponseBodyWriter/writeFile(atPath:offset:length:)``
//  (G5): reads the region in bounded 64 KiB chunks and pushes each through the writer — the framing-
//  agnostic path every engine can use (h1 chunked, h2 DATA, h3), and the fallback when a transport has
//  no `sendfile(2)`. Fails closed on a short file: the response head (incl. `Content-Length`) is
//  already committed by the time a body streams, so under-delivering silently would desync the
//  connection (audit F1) — the stream errors instead and the connection closes.
//

internal import Foundation

/// Streams a file region through a ``ResponseBodyWriter`` in bounded chunks (the copying path).
enum FileRegionStreamer {
    /// Why a file region could not be delivered in full.
    enum FileError: Error {
        /// The file could not be opened (removed or permissions changed after classification).
        case unreadable
        /// The file ended before the framed length (truncated between classification and read).
        case truncated
    }

    /// Streams `length` octets at `offset` from `path` to `writer` in 64 KiB chunks.
    static func stream(
        atPath path: String,
        offset: Int,
        length: Int,
        to writer: any ResponseBodyWriter
    ) async throws {
        guard length > 0 else {
            return
        }
        guard let handle = FileHandle(forReadingAtPath: path) else {
            throw FileError.unreadable
        }
        defer { try? handle.close() }
        try handle.seek(toOffset: UInt64(offset))
        var remaining = length
        while remaining > 0 {
            guard let data = try handle.read(upToCount: min(64 * 1_024, remaining)), !data.isEmpty
            else {
                // EOF before the advertised length — never stop silently short.
                throw FileError.truncated
            }
            try await writer.write([UInt8](data))
            remaining -= data.count
        }
    }
}
