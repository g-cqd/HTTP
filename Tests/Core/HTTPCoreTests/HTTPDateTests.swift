//
//  HTTPDateTests.swift
//  HTTPCoreTests
//
//  RFC 9110 §5.6.7 — IMF-fixdate formatting and HTTP-date parsing (IMF-fixdate + the obsolete rfc850 /
//  asctime forms), checked against canonical timestamps and round-trips.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §5.6.7 — HTTP dates")
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

    @Test("parses the preferred IMF-fixdate form (RFC 9110 §5.6.7)")
    func parsesIMFFixdate() {
        #expect(HTTPDate.parse("Sun, 06 Nov 1994 08:49:37 GMT") == 784_111_777)
        #expect(HTTPDate.parse("Thu, 01 Jan 1970 00:00:00 GMT") == 0)
        #expect(HTTPDate.parse("Tue, 29 Feb 2000 00:00:00 GMT") == 951_782_400)
    }

    @Test("parses the obsolete rfc850 and asctime forms a recipient must accept (RFC 9110 §5.6.7)")
    func parsesObsoleteForms() {
        #expect(HTTPDate.parse("Sunday, 06-Nov-94 08:49:37 GMT") == 784_111_777)
        #expect(HTTPDate.parse("Sun Nov  6 08:49:37 1994") == 784_111_777)
    }

    @Test("parse is the exact inverse of imfFixdate (round-trip)")
    func roundTrips() {
        for timestamp in [0, 1, 784_111_777, 951_782_400, 1_700_000_000] {
            #expect(HTTPDate.parse(HTTPDate.imfFixdate(timestamp)) == timestamp)
        }
    }

    @Test("rejects a malformed date without trapping")
    func rejectsMalformed() {
        #expect(HTTPDate.parse("") == nil)
        #expect(HTTPDate.parse("not a date") == nil)
        #expect(HTTPDate.parse("Sun, 06 Foo 1994 08:49:37 GMT") == nil)  // unknown month
        #expect(HTTPDate.parse("Sun, 99 Nov 1994 25:99:99 GMT") == nil)  // fields out of range
        #expect(HTTPDate.parse("Sun, 06 Nov 1994 08:49:37 PST") == nil)  // not GMT
    }
}
