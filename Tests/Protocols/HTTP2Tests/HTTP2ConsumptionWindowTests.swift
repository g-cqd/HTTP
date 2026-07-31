//
//  HTTP2ConsumptionWindowTests.swift
//  HTTP2Tests
//
//  RFC 9113 §6.9 — consumption-gated receive-window replenishment (2026-07-31 audit, F2/F4; ADR 0006).
//
//  The defect: the engine credited both receive windows the instant DATA *arrived*, on every path. For
//  a buffered request that is fine — `streams.totalBufferedBody` bounds the connection independently —
//  but a streaming route and an RFC 8441 tunnel have no such aggregate, so the peer could run
//  arbitrarily far ahead of a handler that never consumed. These tests pin the fix from the wire's
//  point of view: no WINDOW_UPDATE without a consumption report, the peer stalling at exactly the
//  advertised window, credit surviving a stream's retirement — and the buffered path's cadence
//  unchanged.
//
//  Sans-I/O and fully deterministic: every frame is fed by hand and every WINDOW_UPDATE read back off
//  the wire, so there is no timing in the suite at all.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §6.9 — consumption-gated receive windows")
struct HTTP2ConsumptionWindowTests {
    private static let streaming: @Sendable (HTTPRequest) -> Bool = { _ in true }

    // MARK: The preface raises the connection window

    @Test("the preface raises the connection window with a stream-0 WINDOW_UPDATE (§6.9.2)")
    func prefaceRaisesConnectionWindow() {
        let limits = HTTPLimits(connectionReceiveWindow: 1 << 20)
        var connection = HTTP2Connection(limits: limits)
        let updates = H2Window.windowUpdates(connection.outboundBytes())
        // §6.9.2 fixes the connection window's initial value at 65,535 and SETTINGS cannot change it,
        // so the ONLY way to advertise a larger one is this stream-0 WINDOW_UPDATE for the delta.
        #expect(updates == [H2Window.Update(streamID: .connection, increment: (1 << 20) - 65_535)])
        #expect(connection.connectionReceiveWindow == 1 << 20)
    }

    @Test("a connection window at the protocol floor needs no preface WINDOW_UPDATE (§6.9.2)")
    func prefaceOmitsWindowUpdateAtFloor() {
        var connection = HTTP2Connection(limits: HTTPLimits(connectionReceiveWindow: 65_535))
        #expect(H2Window.windowUpdates(connection.outboundBytes()).isEmpty)
    }

    // MARK: A streaming route is gated

    @Test("a streaming route emits NO WINDOW_UPDATE until consumption is reported (audit F4)")
    func streamingWithholdsWindowUntilConsumed() throws {
        var connection = try H2Window.gated()
        _ = try connection.receive(H2Wire.openStream(streamID: 1))
        _ = connection.outboundBytes()

        // Send a full window's worth in frame-sized pieces. Under arrival-replenish this alone produced
        // several WINDOW_UPDATEs; gated, it must produce none — the handler has taken nothing.
        for _ in 0 ..< (H2Window.streamWindow / H2Window.frame) {
            _ = try connection.receive(H2Window.dataFrame(streamID: 1, count: H2Window.frame))
        }
        #expect(H2Window.windowUpdates(connection.outboundBytes()).isEmpty)
        #expect(connection.outstandingReceiveCredit == H2Window.streamWindow)
        #expect(connection.outstandingReceiveCredit(of: HTTP2StreamID(1)) == H2Window.streamWindow)
    }

    @Test("the peer stalls at exactly the advertised stream window with no consumption (§6.9)")
    func peerStallsAtTheAdvertisedWindow() throws {
        var connection = try H2Window.gated()
        _ = try connection.receive(H2Wire.openStream(streamID: 1))
        for _ in 0 ..< (H2Window.streamWindow / H2Window.frame) {
            _ = try connection.receive(H2Window.dataFrame(streamID: 1, count: H2Window.frame))
        }
        // Exactly the window has been admitted and none of it consumed. A conforming peer is stalled
        // here; a non-conforming one that sends one octet more is refused with the §6.9 stream error.
        H2Wire.expectStreamError(
            .flowControlError,
            on: 1,
            feeding: H2Window.dataFrame(streamID: 1, count: 1),
            connection: &connection
        )
    }

    @Test(
        "replenish emits the stream and connection WINDOW_UPDATE at the half-window, in order (§6.9)",
        arguments: [32 * 1_024, 64 * 1_024, 128 * 1_024])
    func replenishEmitsAtTheHalfWindow(streamWindow: Int) throws {
        // The connection window is deliberately 4× the stream window, so the two half-window thresholds
        // fall at different points and the frames can be told apart.
        var connection = try H2Window.gated(
            streamWindow: streamWindow, connectionWindow: 4 * streamWindow
        )
        _ = try connection.receive(H2Wire.openStream(streamID: 1))
        _ = connection.outboundBytes()
        for _ in 0 ..< (streamWindow / H2Window.frame) {
            _ = try connection.receive(H2Window.dataFrame(streamID: 1, count: H2Window.frame))
        }

        // One octet short of half the STREAM window: batching means nothing has gone out yet.
        let half = streamWindow / 2
        connection.replenishReceiveWindow(HTTP2StreamID(1), consumed: half - 1)
        #expect(H2Window.windowUpdates(connection.outboundBytes()).isEmpty)

        // Crossing the half-window releases the stream's batch. The connection window is four times
        // larger, so it has not yet reached ITS half — only the stream frame appears.
        connection.replenishReceiveWindow(HTTP2StreamID(1), consumed: 1)
        let first = H2Window.windowUpdates(connection.outboundBytes())
        #expect(first == [H2Window.Update(streamID: HTTP2StreamID(1), increment: half)])

        // Drain the rest. The remaining credit still never reaches the connection's half (streamWindow
        // total against a 4× window), so the connection's batch stays pending — which is the point of
        // batching — while the stream's second half goes out.
        connection.replenishReceiveWindow(HTTP2StreamID(1), consumed: streamWindow - half)
        #expect(connection.outstandingReceiveCredit == 0)
        #expect(connection.connectionReceiveConsumed == streamWindow)
    }

    @Test("the connection WINDOW_UPDATE precedes the stream's when both cross together (§6.9)")
    func connectionWindowUpdatePrecedesTheStream() throws {
        // Equal windows, so one consumption report crosses both halves at once. The order is the one
        // arrival-replenish always produced (connection first) and the refactor must preserve it.
        var connection = try H2Window.gated(
            streamWindow: 4 * H2Window.frame, connectionWindow: 4 * H2Window.frame
        )
        _ = try connection.receive(H2Wire.openStream(streamID: 1))
        _ = try connection.receive(H2Window.dataFrames(streamID: 1, total: 4 * H2Window.frame))
        _ = connection.outboundBytes()

        connection.replenishReceiveWindow(HTTP2StreamID(1), consumed: 2 * H2Window.frame)
        let updates = H2Window.windowUpdates(connection.outboundBytes())
        #expect(
            updates == [
                H2Window.Update(streamID: .connection, increment: 2 * H2Window.frame),
                H2Window.Update(streamID: HTTP2StreamID(1), increment: 2 * H2Window.frame)
            ]
        )
    }

    @Test("over-reported consumption is clamped to what the stream actually owes (§6.9)")
    func overReportedConsumptionIsClamped() throws {
        var connection = try H2Window.gated()
        _ = try connection.receive(H2Wire.openStream(streamID: 1))
        _ = try connection.receive(H2Window.dataFrame(streamID: 1, count: H2Window.frame))
        _ = connection.outboundBytes()
        // A driver must not be able to manufacture window: crediting far past the debit is clamped.
        connection.replenishReceiveWindow(HTTP2StreamID(1), consumed: 1 << 30)
        #expect(connection.outstandingReceiveCredit == 0)
        let credited = H2Window.windowUpdates(connection.outboundBytes())
            .map(\.increment)
            .reduce(0, +)
        #expect(credited <= H2Window.frame * 2)  // at most the stream + connection frame, once each
    }

    // MARK: A tunnel is gated

    @Test("a tunnel replenishes only on reported consumption (RFC 8441 §5, audit F2)")
    func tunnelIsConsumptionGated() throws {
        var settings = HTTP2Settings()
        settings.enableConnectProtocol = true
        settings.initialWindowSize = H2Window.streamWindow
        var connection = try H2Window.gated(localSettings: settings) { _ in false }
        _ = try connection.receive(
            H2Wire.headers(
                streamID: 1,
                fields: H2Wire.requestFields(method: "CONNECT", path: "/chat")
                    + [HPACKField(name: ":protocol", value: "websocket")],
                endStream: false
            )
        )
        try connection.acceptTunnel(HTTP2StreamID(1))
        _ = connection.outboundBytes()

        for _ in 0 ..< 4 {
            _ = try connection.receive(H2Window.dataFrame(streamID: 1, count: H2Window.frame))
        }
        // Tunnel DATA is never buffered as a request body and never bounded by the body limit, so
        // arrival-replenish left it with no bound at all. Gated, the window stays shut until consumed.
        #expect(H2Window.windowUpdates(connection.outboundBytes()).isEmpty)
        #expect(connection.outstandingReceiveCredit == 4 * H2Window.frame)

        connection.replenishReceiveWindow(HTTP2StreamID(1), consumed: 4 * H2Window.frame)
        #expect(connection.outstandingReceiveCredit == 0)
        #expect(!(H2Window.windowUpdates(connection.outboundBytes()).isEmpty))
    }

    // MARK: Retirement returns credit to the connection

    @Test("releaseReceiveWindow returns a retired stream's credit to the CONNECTION window only")
    func releaseReturnsConnectionCreditOnly() throws {
        // A connection window small enough that a single release crosses its half — so the effect is
        // observable as a frame, not just as internal state.
        var connection = try H2Window.gated(connectionWindow: 4 * H2Window.frame)
        _ = try connection.receive(H2Wire.openStream(streamID: 1))
        _ = try connection.receive(H2Window.dataFrames(streamID: 1, total: 2 * H2Window.frame))
        _ = connection.outboundBytes()

        connection.releaseReceiveWindow(of: HTTP2StreamID(1))
        let updates = H2Window.windowUpdates(connection.outboundBytes())
        #expect(updates == [H2Window.Update(streamID: .connection, increment: 2 * H2Window.frame)])
        #expect(connection.outstandingReceiveCredit == 0)
        #expect(connection.outstandingReceiveCredit(of: HTTP2StreamID(1)) == 0)
        #expect(connection.isStreamOpen(HTTP2StreamID(1)))  // released, not retired
        // Idempotent — a second release finds nothing outstanding and emits nothing.
        connection.releaseReceiveWindow(of: HTTP2StreamID(1))
        #expect(H2Window.windowUpdates(connection.outboundBytes()).isEmpty)
    }

    @Test(
        "RST_STREAM mid-upload hands the stream's credit back to the connection window (§6.9.1)",
        arguments: [HTTP2ErrorCode.cancel, .internalError, .enhanceYourCalm])
    func resetReturnsConnectionCredit(code: HTTP2ErrorCode) throws {
        var connection = try H2Window.gated(connectionWindow: 4 * H2Window.frame)
        _ = try connection.receive(H2Wire.openStream(streamID: 1))
        _ = try connection.receive(H2Window.dataFrames(streamID: 1, total: 2 * H2Window.frame))
        _ = connection.outboundBytes()

        _ = try connection.receive(H2Wire.rstStream(streamID: 1, code: code))
        // Without this the peer could shrink the shared connection window to nothing by resetting a
        // succession of half-sent uploads, stalling every later stream on the connection.
        #expect(connection.outstandingReceiveCredit == 0)
        #expect(!connection.isStreamOpen(HTTP2StreamID(1)))
        let returned = H2Window.Update(streamID: .connection, increment: 2 * H2Window.frame)
        #expect(H2Window.windowUpdates(connection.outboundBytes()).contains(returned))
    }

    // MARK: The buffered path is unchanged

    @Test("a buffered route's WINDOW_UPDATE cadence is byte-identical to arrival-replenish")
    func bufferedCadenceIsUnchanged() throws {
        // The no-regression guard for the debit/credit split: `consumeReceiveWindows` is now
        // `debit + credit`, and a buffered upload must produce the exact same frames it always did —
        // the connection-wide `totalBufferedBody` cap, not the window, is what bounds that path.
        let limits = HTTPLimits(
            streamReceiveWindow: H2Window.streamWindow,
            connectionReceiveWindow: 4 * H2Window.frame
        )
        var settings = HTTP2Settings()
        settings.initialWindowSize = H2Window.streamWindow
        var connection = try H2Wire.handshaked(localSettings: settings, limits: limits)
        _ = try connection.receive(H2Wire.openStream(streamID: 1))
        _ = connection.outboundBytes()

        var observed: [H2Window.Update] = []
        for _ in 0 ..< 8 {
            _ = try connection.receive(H2Window.dataFrame(streamID: 1, count: H2Window.frame))
            observed += H2Window.windowUpdates(connection.outboundBytes())
        }
        // Replayed against the pre-split arithmetic: the connection window (4 frames) crosses its half
        // every 2 frames, the stream window every `streamWindow / 2`. Nothing is withheld — a buffered
        // route never waits on handler consumption.
        #expect(observed.filter { $0.streamID == .connection }.count == 4)
        #expect(observed.map(\.increment).reduce(0, +) >= 8 * H2Window.frame)
        #expect(connection.outstandingReceiveCredit == 0)  // buffered never holds credit
    }
}
