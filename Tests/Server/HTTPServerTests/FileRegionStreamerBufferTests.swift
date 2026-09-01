//
//  FileRegionStreamerBufferTests.swift
//  HTTPServerTests
//
//  ``FileRegionStreamer`` handed every chunk to the writer as `Array(chunk[..<count])`. That measured
//  zero-copy for a *full* chunk — `Array.init(ArraySlice)` is identity-preserving when the slice covers
//  the whole array — but copied the ragged tail and every short read, and left the zero-copy property
//  resting on an unspecified stdlib fast path. The pump now resizes one buffer in place.
//
//  The oracle is the buffer's base address, not a wall-clock number: one address across every chunk,
//  tail included, *is* the allocation count, and a loaded host cannot confound it.
//

internal import Foundation
import Testing

@testable import HTTPServer

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// The pump's chunk bound (``FileRegionStreamer/chunkSize``), restated so the expectations can derive a
/// chunk count from a region length.
private let pumpChunkSize = 64 * 1_024

/// Exactly one chunk, three whole chunks, and a ragged tail — the tail used to cost its own allocation.
private let regionSizes: [Int] = [pumpChunkSize, 3 * pumpChunkSize, 2 * pumpChunkSize + 7]

/// Writes `count` deterministic octets to a temporary file and adopts it as an ``OpenedFile``.
private func temporaryFile(octets count: Int) throws -> OpenedFile {
    let path = FileManager.default.temporaryDirectory
        .appendingPathComponent("region-\(UUID().uuidString).bin")
    let bytes = (0 ..< count).map { UInt8(truncatingIfNeeded: $0) }
    try Data(bytes).write(to: path)
    defer { try? FileManager.default.removeItem(at: path) }
    let descriptor = path.path.withCString { open($0, O_RDONLY | O_CLOEXEC) }
    return try #require(OpenedFile.adopting(descriptor))
}

@Test("G5 — the file-region pump reuses one buffer for every chunk", arguments: regionSizes)
func pumpReusesOneChunkBuffer(size: Int) async throws {
    let file = try temporaryFile(octets: size)
    let writer = RecordingBodyWriter()
    try await FileRegionStreamer.stream(
        FileRegion(file: file, offset: 0, length: size),
        to: writer
    )
    #expect(writer.counts.count == (size + pumpChunkSize - 1) / pumpChunkSize)
    #expect(writer.counts.reduce(0, +) == size)
    #expect(Set(writer.addresses).count == 1, "the pump allocated a buffer per chunk")
}

@Test("G5 — the pump still delivers the region's exact octets")
func pumpDeliversExactOctets() async throws {
    let size = 2 * pumpChunkSize + 1_234
    let file = try temporaryFile(octets: size)
    let writer = RecordingBodyWriter()
    try await FileRegionStreamer.stream(
        FileRegion(file: file, offset: 100, length: size - 100),
        to: writer
    )
    #expect(writer.bytes == (100 ..< size).map { UInt8(truncatingIfNeeded: $0) })
}
