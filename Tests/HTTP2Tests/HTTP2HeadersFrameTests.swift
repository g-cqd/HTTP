//
//  HTTP2HeadersFrameTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for RFC 9113 §6.2 HEADERS field-block extraction: stripping the PADDED pad-length
//  and trailing padding, skipping the PRIORITY section, both together, and the over-long padding error.
//

import Testing

@testable import HTTP2

@Suite("RFC 9113 §6.2 — HEADERS field block")
struct HTTP2HeadersFrameTests {

    private func fragment(_ payload: [UInt8], _ flags: HTTP2FrameFlags) throws -> [UInt8] {
        Array(try HTTP2HeadersFrame.fieldBlockFragment(payload, flags: flags))
    }

    private func errorCode(_ payload: [UInt8], _ flags: HTTP2FrameFlags) -> HTTP2ErrorCode? {
        do {
            _ = try fragment(payload, flags)
            return nil
        } catch let error as HTTP2Error {
            return error.code
        } catch {
            return nil
        }
    }

    @Test("returns the whole payload when no flags are set")
    func noFlags() throws {
        #expect(try fragment([1, 2, 3], []) == [1, 2, 3])
    }

    @Test("strips the pad length and trailing padding (PADDED)")
    func padded() throws {
        // pad length 2, fragment [10, 11, 12], then two padding octets.
        #expect(try fragment([2, 10, 11, 12, 0, 0], .padded) == [10, 11, 12])
    }

    @Test("skips the five-octet priority section (PRIORITY)")
    func priority() throws {
        // five priority octets, then fragment [10, 11].
        #expect(try fragment([0x80, 0, 0, 1, 16, 10, 11], .priority) == [10, 11])
    }

    @Test("handles PADDED and PRIORITY together")
    func paddedAndPriority() throws {
        // pad length 1, five priority octets, fragment [9, 9], one padding octet.
        #expect(try fragment([1, 0, 0, 0, 0, 0, 9, 9, 0], [.padded, .priority]) == [9, 9])
    }

    @Test("padding exceeding the payload is a PROTOCOL_ERROR (§6.2)")
    func paddingTooLong() {
        // pad length 10, but only three octets remain after it.
        #expect(errorCode([10, 1, 2, 3], .padded) == .protocolError)
    }
}
