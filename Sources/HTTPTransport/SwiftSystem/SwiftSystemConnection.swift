//
//  SwiftSystemConnection.swift
//  HTTPTransport
//
//  A TransportConnection over an accepted socket, using apple/swift-system's typed FileDescriptor
//  for read/write/close (with Errno errors). Blocking syscalls are run on a dispatch queue and
//  bridged to async via continuations.
//
//  Standards: read()/write()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017 / The Open Group Base
//  Specifications Issue 7). The byte stream is TCP (RFC 9293) over IPv4 (RFC 791).
//

internal import Dispatch
internal import SystemPackage

/// A ``TransportConnection`` backed by a swift-system `FileDescriptor` over an accepted socket.
///
/// The descriptor is a trivial value and the per-connection HTTP request/response cycle serializes
/// I/O, so the wrapper is `@unchecked Sendable`; blocking `read`/`write` run on `ioQueue`.
public final class SwiftSystemConnection: TransportConnection, @unchecked Sendable {

    /// The connection's stable identifier.
    public let id: TransportConnectionID

    /// The peer's address.
    public let peer: TransportAddress

    private let descriptor: FileDescriptor
    private let ioQueue: DispatchQueue

    /// Wraps an accepted socket `descriptor`.
    init(
        id: TransportConnectionID,
        descriptor: FileDescriptor,
        peer: TransportAddress,
        ioQueue: DispatchQueue
    ) {
        self.id = id
        self.peer = peer
        self.descriptor = descriptor
        self.ioQueue = ioQueue
    }

    /// Reads up to `maxLength` bytes (blocking on `ioQueue`), or `nil` at end of stream.
    public func receive(maxLength: Int) async throws -> [UInt8]? {
        let descriptor = self.descriptor
        let queue = self.ioQueue
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    var buffer = [UInt8](repeating: 0, count: max(1, maxLength))
                    let count = try buffer.withUnsafeMutableBytes { try descriptor.read(into: $0) }
                    if count == 0 {
                        continuation.resume(returning: nil)  // EOF
                    } else {
                        continuation.resume(returning: Array(buffer[0..<count]))
                    }
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Writes all of `bytes` (blocking on `ioQueue`, handling partial writes).
    public func send(_ bytes: [UInt8]) async throws {
        let descriptor = self.descriptor
        let queue = self.ioQueue
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            queue.async {
                do {
                    try bytes.withUnsafeBytes { raw in
                        var offset = 0
                        while offset < raw.count {
                            let written = try descriptor.write(
                                UnsafeRawBufferPointer(rebasing: raw[offset...]))
                            offset += written
                        }
                    }
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Closes the descriptor.
    public func close() async {
        try? descriptor.close()
    }
}
