//
//  FileRegion.swift
//  HTTPServer
//
//  What a responder hands a ``ResponseBodyWriter`` instead of a pathname (G5 static serving): a byte
//  range of an ALREADY-OPEN, already-verified file. Carrying the ``OpenedFile`` rather than a path is the
//  whole point — the region keeps the verified descriptor alive for the life of the response, so the
//  writer never re-resolves anything and a rename landed mid-stream cannot swap the bytes on the wire out
//  from under the `Content-Length` already framed for them (CWE-367, CWE-59).
//

/// A byte range of an already-open, already-verified file.
public struct FileRegion: Sendable {
    /// The open, verified file — held so its descriptor stays open for the whole response.
    public let file: OpenedFile

    /// The first octet of the region, as an offset from the start of the file.
    public let offset: Int

    /// The region's length in octets.
    public let length: Int

    /// The verified descriptor to `pread(2)` or `sendfile(2)` from.
    public var descriptor: Int32 {
        file.descriptor
    }

    /// Creates a region covering `length` octets of `file` starting at `offset`.
    public init(file: OpenedFile, offset: Int, length: Int) {
        self.file = file
        self.offset = offset
        self.length = length
    }
}
