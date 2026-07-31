//
//  HTTP2HeadersFrame.swift
//  HTTP2
//
//  RFC 9113 §6.2 — extracting the field block fragment from a HEADERS frame payload. A HEADERS payload
//  may be prefixed by a one-octet Pad Length (PADDED) and a five-octet priority section (PRIORITY),
//  and suffixed by padding. The field block fragment is what remains. Padding larger than the payload
//  is a PROTOCOL_ERROR (§6.2). Priority is advisory in RFC 9113 (§5.3.2), so the section is skipped.
//

/// Field-block extraction from a HEADERS frame payload (RFC 9113 §6.2).
public enum HTTP2HeadersFrame {
    private static let priorityFieldLength = 5

    /// Returns the field block fragment of a HEADERS `payload`, given its `flags` (RFC 9113 §6.2).
    ///
    /// Strips the optional PADDED pad-length octet and trailing padding, then the optional 5-octet
    /// PRIORITY section. A pad length that leaves no room for the rest is a PROTOCOL_ERROR.
    public static func fieldBlockFragment(
        _ payload: [UInt8],
        flags: HTTP2FrameFlags
    ) throws(HTTP2Error) -> ArraySlice<UInt8> {
        payload[try fieldBlockRange(count: payload.count, padLength: payload.first, flags: flags)]
    }

    /// Returns the range of the field block fragment within a borrowed HEADERS `payload` (§6.2).
    ///
    /// The zero-copy entry point: the connection engine slices the fragment out of the inbound buffer
    /// in place rather than copying the payload to find it (audit CR-F18).
    static func fieldBlockRange(
        _ payload: RawSpan,
        flags: HTTP2FrameFlags
    ) throws(HTTP2Error) -> Range<Int> {
        try fieldBlockRange(
            count: payload.byteCount,
            padLength: payload.byteCount > 0
                ? payload.unsafeLoad(fromByteOffset: 0, as: UInt8.self) : nil,
            flags: flags
        )
    }

    /// The §6.2 fragment bounds within a payload of `count` octets whose first octet is `padLength`.
    ///
    /// Pure arithmetic on the two facts either representation can supply, so the owning and borrowed
    /// entry points above cannot drift apart about where a fragment starts or ends.
    private static func fieldBlockRange(
        count: Int,
        padLength: UInt8?,
        flags: HTTP2FrameFlags
    ) throws(HTTP2Error) -> Range<Int> {
        var start = 0
        var end = count

        if flags.contains(.padded) {
            guard let padLength else {
                throw .connection(.protocolError, "PADDED HEADERS missing the pad-length octet")
            }
            start += 1
            end -= Int(padLength)
            guard end >= start else {
                throw .connection(.protocolError, "HEADERS padding exceeds the payload")
            }
        }

        if flags.contains(.priority) {
            guard end - start >= priorityFieldLength else {
                throw .connection(.frameSizeError, "HEADERS missing the priority section")
            }
            start += priorityFieldLength
        }
        return start ..< end
    }

    /// The stream dependency declared in a HEADERS frame's deprecated priority section (RFC 9113
    /// §5.3.2 / §6.2), or `nil` when the PRIORITY flag is clear.
    ///
    /// The priority section follows the optional PADDED pad-length octet: a 1-bit exclusive flag, a
    /// 31-bit stream dependency, then an 8-bit weight. Only the dependency is read — to reject a
    /// stream that depends on itself (RFC 9113 §5.3.1). Truncated input returns `nil`; the real
    /// length check is ``fieldBlockFragment(_:flags:)``, which the caller invokes alongside this.
    public static func priorityDependency(
        _ payload: [UInt8],
        flags: HTTP2FrameFlags
    ) -> HTTP2StreamID? {
        guard flags.contains(.priority) else {
            return nil
        }
        let offset = flags.contains(.padded) ? 1 : 0
        guard payload.count >= offset + priorityFieldLength else {
            return nil
        }
        let dependency =
            (UInt32(payload[offset]) << 24 | UInt32(payload[offset + 1]) << 16
                | UInt32(payload[offset + 2]) << 8 | UInt32(payload[offset + 3])) & 0x7FFF_FFFF
        return HTTP2StreamID(rawValue: dependency)
    }

    /// The stream dependency in a borrowed HEADERS payload's priority section, if it has one.
    ///
    /// RFC 9113 §5.3.2 / §6.2; nil when the PRIORITY flag is clear.
    ///
    /// The zero-copy counterpart of ``priorityDependency(_:flags:)`` — same 31-bit read, taken
    /// straight out of the inbound buffer.
    static func priorityDependency(
        _ payload: RawSpan,
        flags: HTTP2FrameFlags
    ) -> HTTP2StreamID? {
        guard flags.contains(.priority) else {
            return nil
        }
        let offset = flags.contains(.padded) ? 1 : 0
        guard payload.byteCount >= offset + priorityFieldLength else {
            return nil
        }
        let dependency = UInt32(
            bigEndian: payload.unsafeLoadUnaligned(fromByteOffset: offset, as: UInt32.self)
        )
        return HTTP2StreamID(rawValue: dependency & 0x7FFF_FFFF)
    }
}
