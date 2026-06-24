//
//  HTTP2FlowControlWindowTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for the RFC 9113 §6.9 flow-control window: reserving send capacity, WINDOW_UPDATE
//  increments, the zero-increment and 2^31-1 overflow reports, and the negative window after a
//  SETTINGS shrink (§6.9.2).
//

import Testing

@testable import HTTP2

@Suite("RFC 9113 §6.9 — flow-control window")
struct HTTP2FlowControlWindowTests {
    @Test("starts at the initial size")
    func initial() {
        #expect(HTTP2FlowControlWindow(initialSize: 65_535).available == 65_535)
    }

    @Test("reserve grants up to the available window, then nothing")
    func reserve() {
        var window = HTTP2FlowControlWindow(initialSize: 1_000)
        #expect(window.reserve(400) == 400)
        #expect(window.size == 600)
        #expect(window.reserve(1_000) == 600)  // only what remains
        #expect(window.size == 0)
        #expect(window.reserve(10) == 0)  // empty
    }

    @Test("WINDOW_UPDATE increases the window (§6.9)")
    func increase() {
        var window = HTTP2FlowControlWindow(initialSize: 0)
        #expect(window.increase(by: 5_000) == .applied)
        #expect(window.size == 5_000)
    }

    @Test("a zero increment is reported as a PROTOCOL_ERROR (§6.9)")
    func zeroIncrement() {
        var window = HTTP2FlowControlWindow(initialSize: 100)
        #expect(window.increase(by: 0) == .zeroIncrement)
        #expect(window.size == 100)  // unchanged
    }

    @Test("an increment past 2^31-1 is a FLOW_CONTROL_ERROR (§6.9.1)")
    func overflow() {
        var window = HTTP2FlowControlWindow(initialSize: HTTP2FlowControlWindow.maxSize)
        #expect(window.increase(by: 1) == .overflow)
        #expect(window.size == HTTP2FlowControlWindow.maxSize)  // unchanged
    }

    @Test("a SETTINGS shrink can drive the window negative (§6.9.2)")
    func negativeWindow() {
        var window = HTTP2FlowControlWindow(initialSize: 100)
        #expect(window.shiftInitial(by: -300) == .applied)
        #expect(window.size == -200)
        #expect(window.available == 0)
        #expect(window.reserve(50) == 0)  // nothing may be sent while negative
    }

    // MARK: Boundary exactness (mutation-resistance; see Tests/MUTATION-OPERATORS.md M1/M4/M7/M9)

    @Test("WINDOW_UPDATE lands exactly on 2^31-1, overflows one past it (§6.9.1)")
    func increaseBoundary() {
        var window = HTTP2FlowControlWindow(initialSize: HTTP2FlowControlWindow.maxSize - 100)
        #expect(window.increase(by: 100) == .applied)  // delta == maxSize - size: lands on the cap
        #expect(window.size == HTTP2FlowControlWindow.maxSize)
        #expect(window.increase(by: 1) == .overflow)  // one past the cap
        #expect(window.size == HTTP2FlowControlWindow.maxSize)  // unchanged
    }

    @Test("a SETTINGS grow lands exactly on 2^31-1, overflows one past it (§6.9.2)")
    func shiftInitialBoundary() {
        var window = HTTP2FlowControlWindow(initialSize: HTTP2FlowControlWindow.maxSize - 50)
        #expect(window.shiftInitial(by: 51) == .overflow)  // one past the cap
        #expect(window.size == HTTP2FlowControlWindow.maxSize - 50)  // unchanged
        #expect(window.shiftInitial(by: 50) == .applied)  // lands exactly on the cap
        #expect(window.size == HTTP2FlowControlWindow.maxSize)
    }

    @Test("a zero SETTINGS shift applies (unlike WINDOW_UPDATE, §6.9.2 has no zero rule)")
    func shiftInitialZeroApplies() {
        var window = HTTP2FlowControlWindow(initialSize: 100)
        #expect(window.shiftInitial(by: 0) == .applied)  // not .zeroIncrement
        #expect(window.size == 100)
    }

    @Test("reserve never grants a negative or zero request")
    func reserveIgnoresNonPositiveRequest() {
        var window = HTTP2FlowControlWindow(initialSize: 1_000)
        #expect(window.reserve(-5) == 0)
        #expect(window.size == 1_000)  // untouched — must not credit the window
        #expect(window.reserve(0) == 0)
        #expect(window.size == 1_000)
    }
}
