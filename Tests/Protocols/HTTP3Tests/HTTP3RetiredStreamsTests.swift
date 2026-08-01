//
//  HTTP3RetiredStreamsTests.swift
//  HTTP3Tests
//
//  The bookkeeping behind terminal retirement (audit R5-P0c), on its own.
//
//  Two properties fight each other here and both matter. Terminality: an id that has been retired must
//  never be admitted again, or queued octets resurrect the stream. Liveness: an id that has *not* been
//  retired must always be admitted, however high the ids around it have climbed, or a live request is
//  silently dropped. A bare highest-id watermark satisfies the first and violates the second, which is
//  exactly what the R5-P0b racing test caught.
//
//  Standards: RFC 9000 §2.1 (client-initiated bidirectional ids advance by 4); CWE-770.
//

import HTTPCore
import Testing

@testable import HTTP3

@Suite("HTTP/3 — the retired-stream run is terminal and bounded (R5-P0c)")
struct HTTP3RetiredStreamsTests {
    @Test("nothing is retired before anything retires")
    func nothingIsRetiredInitially() {
        let retired = HTTP3RetiredStreams()

        #expect(!retired.contains(QUICStreamID(0)))
        #expect(!retired.contains(QUICStreamID(4)))
        #expect(retired.watermark == nil)
    }

    @Test("retiring in id order advances the run one stride at a time", arguments: [1, 2, 8, 64])
    func inOrderRetirementAdvancesTheRun(_ count: Int) {
        var retired = HTTP3RetiredStreams()

        for index in 0 ..< count {
            retired.retire(QUICStreamID(UInt64(index) * 4))
        }

        #expect(retired.watermark == QUICStreamID(UInt64(count - 1) * 4))
        for index in 0 ..< count {
            #expect(retired.contains(QUICStreamID(UInt64(index) * 4)))
        }
        #expect(!retired.contains(QUICStreamID(UInt64(count) * 4)))
    }

    @Test("an out-of-order retirement never covers the ids below it")
    func outOfOrderRetirementCoversOnlyItself() {
        var retired = HTTP3RetiredStreams()

        retired.retire(QUICStreamID(12))

        #expect(retired.contains(QUICStreamID(12)))
        // The whole trap: 0, 4 and 8 are live streams that simply have not spoken yet.
        #expect(!retired.contains(QUICStreamID(0)))
        #expect(!retired.contains(QUICStreamID(4)))
        #expect(!retired.contains(QUICStreamID(8)))
        #expect(retired.watermark == nil)
    }

    @Test("filling the gap closes the run over everything retired out of order")
    func fillingTheGapClosesTheRun() {
        var retired = HTTP3RetiredStreams()

        retired.retire(QUICStreamID(8))
        retired.retire(QUICStreamID(0))
        #expect(retired.watermark == QUICStreamID(0))
        #expect(!retired.contains(QUICStreamID(4)))

        retired.retire(QUICStreamID(4))

        #expect(retired.watermark == QUICStreamID(8))
        #expect(retired.contains(QUICStreamID(4)))
        #expect(retired.contains(QUICStreamID(8)))
    }

    @Test("a unidirectional id is never retired — §6.2 streams are long-lived")
    func unidirectionalIDsAreNotRetired() {
        var retired = HTTP3RetiredStreams()

        retired.retire(QUICStreamID(2))  // the peer's control stream (RFC 9000 §2.1)
        retired.retire(QUICStreamID(6))  // its QPACK encoder stream

        #expect(!retired.contains(QUICStreamID(2)))
        #expect(!retired.contains(QUICStreamID(6)))
        #expect(retired.watermark == nil)
    }

    @Test("the out-of-order remainder cannot grow without bound")
    func theRemainderIsBounded() {
        var retired = HTTP3RetiredStreams()

        // Every id retires except 0, so the run can never start from its proper beginning and the
        // remainder is the only place they can go — the shape a peer would use to grow it (CWE-770).
        let count = HTTP3RetiredStreams.capacity * 4
        for index in 1 ... count {
            retired.retire(QUICStreamID(UInt64(index) * 4))
        }

        // The fold gives up on the missing id and starts the run anyway, which then closes over
        // everything above it — so the remainder collapses rather than growing with the connection.
        // Giving up is the documented over-approximation, and it is bounded in *when*, not just in
        // size: it takes `capacity` retirements of ids the missing one never joined, by which point a
        // stream that has sent nothing has long since been reaped by its own header deadline.
        let highest = QUICStreamID(UInt64(count) * 4)
        #expect(retired.watermark == highest, "the run absorbs the remainder, not accumulates it")
        #expect(retired.contains(highest))
    }

    @Test("a gap well inside the cap is still held open, not folded away")
    func aGapInsideTheCapIsHeldOpen() {
        var retired = HTTP3RetiredStreams()

        // Half the cap's worth of out-of-order retirements: nowhere near the backstop, so id 0 stays
        // admissible. This is the case that actually happens — a slow stream among fast ones.
        for index in 1 ... (HTTP3RetiredStreams.capacity / 2) {
            retired.retire(QUICStreamID(UInt64(index) * 4))
        }

        #expect(!retired.contains(QUICStreamID(0)))
        #expect(retired.watermark == nil)
    }
}
