//
//  AllocationsTests.swift
//  HTTPTestSupportTests
//
//  The allocation oracles measure what they claim. ``mallocByteDelta(_:)`` in particular has to see
//  the *size* libmalloc was asked for, including a large single allocation, because the guard it
//  backs is "a small input plus a large cap must not become a large allocation" (CWE-409) — an
//  allocation *count* cannot express that.
//

import HTTPTestSupport
import Testing

@Test("the byte oracle charges a large single allocation its full size")
func byteDeltaSeesALargeAllocation() {
    let size = 8 << 20  // 8 MiB, far above any allocator small/nano bucket
    var sink = 0
    _ = mallocByteDelta { sink = [UInt8](repeating: 0, count: 8).count }  // warm up
    let measured = mallocByteDelta {
        var buffer = [UInt8](repeating: 0, count: size)
        buffer[size - 1] = 1
        sink = buffer.count
    }
    #expect(sink == size)
    guard let measured else {
        return  // counting unavailable on this platform: the body still ran
    }
    #expect(measured >= size)
    #expect(measured < size * 4)
}

@Test("the byte oracle charges geometric growth far less than its worst-case bound")
func byteDeltaDistinguishesGrowthFromPreallocation() {
    let cap = 8 << 20
    var sink = 0
    _ = mallocByteDelta { sink = [UInt8]().count }  // warm up
    let grown = mallocByteDelta {
        var buffer: [UInt8] = []
        for _ in 0 ..< 1_024 {
            buffer.append(0)
        }
        sink = buffer.count
    }
    #expect(sink == 1_024)
    guard let grown else {
        return
    }
    // Doubling to 1 KiB costs a few KiB in total; reserving the 8 MiB cap up front would not.
    #expect(grown < cap / 8)
}

@Test("an empty measured region costs about nothing")
func byteDeltaIsScoped() {
    let measured = mallocByteDelta {
        // Deliberately empty: the oracle itself must not allocate inside the region it measures.
    }
    #expect(measured ?? 0 < 4_096)
}
