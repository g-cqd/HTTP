//
//  HTTPDateTests.swift
//  HTTPCoreTests
//
//  RFC 9110 §5.6.7 — IMF-fixdate formatting, checked against canonical timestamps.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §5.6.7 — IMF-fixdate")
struct HTTPDateTests {

    @Test("the Unix epoch is Thursday, 01 Jan 1970")
    func epoch() {
        #expect(HTTPDate.imfFixdate(0) == "Thu, 01 Jan 1970 00:00:00 GMT")
    }

    @Test("the RFC 9110 example timestamp formats as in the spec")
    func rfcExample() {
        // RFC 9110 §5.6.7 uses "Sun, 06 Nov 1994 08:49:37 GMT" (Unix time 784111777).
        #expect(HTTPDate.imfFixdate(784_111_777) == "Sun, 06 Nov 1994 08:49:37 GMT")
    }

    @Test("a leap day (29 Feb 2000) formats correctly")
    func leapDay() {
        #expect(HTTPDate.imfFixdate(951_782_400) == "Tue, 29 Feb 2000 00:00:00 GMT")
    }
}
