//
//  RequestBodyCollectTests.swift
//  HTTPServerTests
//
//  ``RequestBody/collect(maximum:expecting:)`` — the bounded buffering entry point (RFC 9110 §15.5.14).
//  It stops reading and fails closed the moment the accumulated body would cross the caller's cap
//  (never after materializing it), reserves from a declared `Content-Length` so a legitimate body is
//  not grown chunk by chunk, and bounds that reservation so an attacker-declared length cannot itself
//  become the allocation (CWE-770).
//

import Testing

@testable import HTTPServer

@Suite("RequestBody — bounded collect (RFC 9110 §15.5.14, CWE-770)")
struct RequestBodyCollectTests {
    @Test("a buffered body at or under the cap is returned unchanged")
    func collectedUnderCap() async {
        let bytes = Array("hello".utf8)
        #expect(await RequestBody.collected(bytes).collect(maximum: 5) == bytes)
        #expect(await RequestBody.collected(bytes).collect(maximum: 1_000) == bytes)
    }

    @Test("a buffered body over the cap fails closed")
    func collectedOverCap() async {
        #expect(await RequestBody.collected(Array("hello".utf8)).collect(maximum: 4) == nil)
    }

    @Test("a streamed body at or under the cap is collected whole")
    func streamedUnderCap() async {
        let producer = PullBodyProducer(chunkCount: 8, size: 16)
        let collected = await producer.makeBody().collect(maximum: 128)
        #expect(collected == producer.allBytes)
        #expect(await producer.isDrained)
    }

    @Test("a streamed body over the cap fails closed WITHOUT draining the producer")
    func streamedOverCapStopsEarly() async {
        // The point of the bound: it must stop *reading*, not merely refuse the buffer it already
        // built. Four 16-octet chunks fit the 64-octet cap; the fifth crosses it, so the producer is
        // asked for five of its sixty-four chunks and no more.
        let producer = PullBodyProducer(chunkCount: 64, size: 16)
        #expect(await producer.makeBody().collect(maximum: 64) == nil)
        #expect(await producer.isDrained == false)
        #expect(await producer.pulled <= 5)
    }

    @Test("a negative cap admits nothing")
    func negativeCapAdmitsNothing() async {
        #expect(await RequestBody.collected([]).collect(maximum: -1) == nil)
        #expect(await PullBodyProducer([[1]]).makeBody().collect(maximum: -1) == nil)
    }

    @Test("an empty body collects to empty under a zero cap")
    func emptyBodyUnderZeroCap() async {
        #expect(await RequestBody.collected([]).collect(maximum: 0)?.isEmpty == true)
    }

    @Test(
        "a declared Content-Length never becomes the allocation, however absurd",
        arguments: [Int.max, Int.max / 2, 1 << 40]
    )
    func declaredLengthDoesNotDriveTheAllocation(declared: Int) async {
        // `reserveCapacity(min(declared, maximum))` would commit the peer's *claim* — a header costs
        // the attacker nothing and would cost the server the whole cap for a body never sent
        // (CWE-770). The reservation is capped, so this completes on the actual eight octets.
        let producer = PullBodyProducer([Array("12345678".utf8)])
        let collected = await producer.makeBody().collect(maximum: .max, expecting: declared)
        #expect(collected == Array("12345678".utf8))
    }

    @Test("a declared length under the reservation ceiling still collects exactly")
    func declaredLengthCollectsExactly() async {
        let producer = PullBodyProducer(chunkCount: 4, size: 1_024)
        let collected = await producer.makeBody().collect(maximum: 8_192, expecting: 4_096)
        #expect(collected == producer.allBytes)
        #expect(collected?.count == 4_096)
    }

    @Test("the unbounded collect() still returns the whole body")
    func unboundedCollectUnchanged() async {
        let producer = PullBodyProducer(chunkCount: 4, size: 32)
        #expect(await producer.makeBody().collect() == producer.allBytes)
    }
}
