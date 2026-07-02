//
//  TransportConnection+SendFile.swift
//  HTTPTransport
//
//  The default (copying) implementation of ``TransportConnection/sendFile(descriptor:offset:length:)``
//  (G5): `pread(2)` the file region into one reused bounded scratch and ``TransportConnection/send(_:)``
//  each chunk — byte-identical to a kernel `sendfile(2)` override, two copies slower (file → scratch,
//  scratch → socket). `pread` (not `read`) so the caller's descriptor offset is never disturbed, and
//  the loop never buffers more than one 64 KiB chunk regardless of file size.
//
//  Standards: pread() per POSIX.1-2017 (IEEE Std 1003.1-2017).
//

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

extension TransportConnection {
    /// Default ``sendFile(descriptor:offset:length:)``: bounded `pread` + ``send(_:)`` chunks.
    ///
    /// Fails closed if the file delivers fewer than `length` octets (the caller has already framed
    /// that length — a silent short body would desync the connection).
    public func sendFile(descriptor: Int32, offset: Int, length: Int) async throws {
        var remaining = length
        var cursor = offset
        var chunk = [UInt8](repeating: 0, count: min(64 * 1_024, max(1, length)))
        while remaining > 0 {
            let wanted = min(chunk.count, remaining)
            let count = chunk.withUnsafeMutableBytes { raw -> Int in
                while true {
                    let read = pread(descriptor, raw.baseAddress, wanted, off_t(cursor))
                    if read >= 0 {
                        return read
                    }
                    if errno == EINTR { continue }
                    return -1
                }
            }
            guard count > 0 else {
                throw TransportError.ioFailed(
                    count == 0
                        ? "sendFile: file ended \(remaining) octet(s) short of the framed length"
                        : "sendFile: pread errno \(errno)"
                )
            }
            try await send(Array(chunk[..<count]))
            cursor += count
            remaining -= count
        }
    }
}
