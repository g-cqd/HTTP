//
//  RecordingBodyWriter.swift
//  HTTPServerTests
//
//  A ``ResponseBodyWriter`` fixture that records what a producer pushed at it: the octets, and the
//  identity of the buffer each chunk arrived in. The address matters because the file-region pump and
//  the compressing writer both claim to reuse one buffer, and a distinct-address count *is* an
//  allocation count — deterministic, unlike a wall-clock number on a shared host.
//
//  It deliberately does **not** retain the chunk arrays. Retaining one would leave it non-uniquely
//  referenced and force the very copy-on-write the address oracle is there to detect.
//

internal import Synchronization

@testable import HTTPServer

/// Collects streamed body octets and the base address of every chunk buffer.
final class RecordingBodyWriter: ResponseBodyWriter, Sendable {
    private let state = Mutex<(bytes: [UInt8], addresses: [UInt], counts: [Int])>(([], [], []))

    deinit {
        // No teardown beyond ARC; the Mutex releases with the instance.
    }

    /// Everything written, concatenated.
    var bytes: [UInt8] {
        state.withLock(\.bytes)
    }

    /// The base address of each chunk buffer, in arrival order.
    var addresses: [UInt] {
        state.withLock(\.addresses)
    }

    /// The octet count of each chunk, in arrival order.
    var counts: [Int] {
        state.withLock(\.counts)
    }

    // swiftlint:disable:next unneeded_throws_rethrows
    func write(_ chunk: [UInt8]) async throws {
        let address = chunk.withUnsafeBufferPointer { UInt(bitPattern: $0.baseAddress) }
        state.withLock { record in
            record.bytes.append(contentsOf: chunk)
            record.addresses.append(address)
            record.counts.append(chunk.count)
        }
    }
}
