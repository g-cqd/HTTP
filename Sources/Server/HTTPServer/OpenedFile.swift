//
//  OpenedFile.swift
//  HTTPServer
//
//  An open, verified regular file: the descriptor plus the `fstat(2)` **of that descriptor**. Every
//  validator that goes on the wire — `Content-Length`, `ETag`, `Last-Modified` — is read from this stat,
//  and every body octet is `pread(2)`/`sendfile(2)` from this descriptor, so a rename or symlink swap
//  landed after resolution can no longer make the head describe one file while the body carries another
//  (CWE-367 time-of-check/time-of-use, CWE-59 link following).
//

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// An open, verified regular file — a descriptor and the `fstat(2)` of that same descriptor.
///
/// Only ``RootDirectory`` and ``OpenedDirectory`` create one, and only by `O_NOFOLLOW` `openat(2)` hops
/// from the root descriptor, so the file is inside the root by construction rather than by a string
/// comparison. The instance owns its descriptor and closes it exactly once, in `deinit`; a
/// ``FileRegion`` holds the instance and therefore keeps the descriptor open for the whole streamed
/// response.
public final class OpenedFile: Sendable {
    /// The verified descriptor: read-only, close-on-exec, and never reached through a symlink.
    public let descriptor: Int32

    /// The size in octets, from the `fstat(2)` of ``descriptor`` — the `Content-Length` on the wire.
    public let size: Int

    /// The modification time in whole seconds since the epoch, from the `fstat(2)` of ``descriptor``.
    public let modifiedAt: Int

    /// Takes ownership of `descriptor`, which `status` must already have shown to be a regular file.
    init(descriptor: Int32, status: stat) {
        self.descriptor = descriptor
        size = Int(status.st_size)
        modifiedAt = POSIXFile.modificationTime(of: status)
    }

    deinit {
        POSIXFile.release(descriptor)
    }

    /// Adopts `descriptor` when it is a regular file; otherwise closes it and returns nil.
    ///
    /// The `fstat(2)` is of the descriptor, not of a name, so nothing can change what is being described
    /// between the check and the read. A FIFO, socket, or device node is refused here (invariant 4): a
    /// serve task must never be able to park on one.
    static func adopting(_ descriptor: Int32) -> OpenedFile? {
        guard let status = POSIXFile.status(of: descriptor), status.st_mode & S_IFMT == S_IFREG
        else {
            POSIXFile.release(descriptor)
            return nil
        }
        return Self(descriptor: descriptor, status: status)
    }

    /// Reads exactly `length` octets at `offset`, or nil when the file cannot deliver that many.
    ///
    /// Fails closed instead of returning a short buffer: the head has already framed ``size``-derived
    /// lengths, and a body that contradicts `Content-Length` would desync the connection (audit F1). An
    /// empty range is the valid empty body.
    func read(offset: Int, length: Int) -> [UInt8]? {
        guard length > 0 else {
            return []
        }
        var complete = false
        let bytes = [UInt8](unsafeUninitializedCapacity: length) { buffer, initialized in
            complete = POSIXFile.readExactly(
                descriptor, into: UnsafeMutableRawBufferPointer(buffer), at: offset
            )
            initialized = complete ? length : 0
        }
        return complete ? bytes : nil
    }
}
