//
//  ChunkRecorder.swift
//  HTTPServerTests
//
//  Records the chunk boundaries a responder actually observed. Chunk *sizes*, in order, are what
//  distinguishes "the middleware forwarded the stream" from "the middleware collected it and handed
//  the responder one buffer" — a total octet count cannot tell those apart.
//

/// Records the size of every request-body chunk a responder received, in order.
actor ChunkRecorder {
    private(set) var sizes: [Int] = []

    /// Records one received chunk of `size` octets.
    func record(_ size: Int) {
        sizes.append(size)
    }
}
