//
//  WebSocketFrameDecoder.swift
//  WebSocket
//
//  RFC 6455 §5.2 — the incremental, sans-I/O frame decoder. It pulls one complete frame (header plus
//  the full payload) from an accumulating buffer, returning nil while a frame is still arriving so the
//  caller can read more, and unmasking the payload (§5.3) in the process. Iterative; no recursion.
//

public import HTTPCore

/// Pulls complete WebSocket frames from an accumulating byte buffer (RFC 6455 §5.2).
public struct WebSocketFrameDecoder {
    /// The largest payload accepted, in octets — a resource-exhaustion guard (default 1 MiB).
    private let maxPayloadLength: Int

    /// Whether every frame must be masked (RFC 6455 §5.1) — true for a server reading client frames.
    private let requireMaskedFrames: Bool

    /// Creates a decoder rejecting payloads larger than `maxPayloadLength`; set `requireMaskedFrames`
    /// for the server role, which MUST receive masked frames (RFC 6455 §5.1).
    public init(maxPayloadLength: Int = 1 << 20, requireMaskedFrames: Bool = false) {
        self.maxPayloadLength = maxPayloadLength
        self.requireMaskedFrames = requireMaskedFrames
    }

    /// Pulls the next complete frame from `reader`, advancing it; returns nil if one is still arriving.
    ///
    /// Validates the reserved bits, opcode, and control-frame constraints (RFC 6455 §5.2 / §5.5),
    /// resolves the 7/16/64-bit payload length, and unmasks the payload (§5.3). Throws on a framing
    /// violation; an incomplete frame leaves `reader` untouched for a later retry.
    public func nextFrame(_ reader: inout ByteReader) throws(WebSocketError) -> WebSocketFrame? {
        // Probe on a copy so an incomplete frame leaves the real cursor untouched (RFC 6455 §5.2).
        var probe = reader
        guard let byte0 = probe.readByte(), let byte1 = probe.readByte() else { return nil }

        let isFinal = byte0 & 0x80 != 0
        guard byte0 & 0x70 == 0 else { throw .reservedBitsSet }  // RSV1–RSV3, no extensions
        let opcode = WebSocketOpcode(rawValue: byte0)
        guard opcode.isDefined else { throw .reservedOpcode(byte0 & 0x0F) }

        let isMasked = byte1 & 0x80 != 0
        guard isMasked || !requireMaskedFrames else { throw .maskingRequired }  // §5.1
        if opcode.isControl {
            guard isFinal else { throw .fragmentedControlFrame }  // §5.5
            guard byte1 & 0x7F <= 125 else { throw .controlFrameTooLong }  // §5.5
        }

        guard let payloadLength = try Self.resolvePayloadLength(byte1 & 0x7F, from: &probe) else {
            return nil
        }
        guard payloadLength <= maxPayloadLength else { throw .payloadTooLong }

        let maskKey = isMasked ? Self.readMaskKey(from: &probe) : nil
        if isMasked, maskKey == nil { return nil }  // key still arriving
        guard probe.remaining >= payloadLength else { return nil }  // payload still arriving

        // Commit: advance the real cursor past the header (the octets the probe consumed) and payload.
        let headerLength = probe.position - reader.position
        reader.advance(by: headerLength)
        let start = reader.position
        reader.advance(by: payloadLength)
        let payload = reader.slice(in: start ..< (start + payloadLength))
            .withUnsafeBytes {
                source in
                if let maskKey { return Self.unmaskedCopy(of: source, with: maskKey) }
                return Array(source)
            }
        return WebSocketFrame(isFinal: isFinal, opcode: opcode, payload: payload)
    }

    /// Resolves the payload length from the 7-bit field (RFC 6455 §5.2): inline, or the next 2 or 8
    /// octets.
    ///
    /// Returns nil if those octets are still arriving; throws on a non-minimal encoding.
    private static func resolvePayloadLength(
        _ length7: UInt8,
        from probe: inout ByteReader
    ) throws(WebSocketError) -> Int? {
        switch length7 {
            case 126:
                guard let high = probe.readByte(), let low = probe.readByte() else { return nil }
                let value = Int(high) << 8 | Int(low)
                guard value > 125 else { throw .nonMinimalLength }  // would fit the 7-bit form
                return value
            case 127:
                var value: UInt64 = 0
                for _ in 0 ..< 8 {
                    guard let byte = probe.readByte() else { return nil }
                    value = value << 8 | UInt64(byte)
                }
                guard value & 0x8000_0000_0000_0000 == 0 else { throw .lengthHighBitSet }
                guard value > 0xFFFF else { throw .nonMinimalLength }  // would fit the 16-bit form
                return Int(value)
            default:
                return Int(length7)
        }
    }

    /// Reads the 4-octet masking key (RFC 6455 §5.3), or nil if it is still arriving.
    private static func readMaskKey(from probe: inout ByteReader) -> (UInt8, UInt8, UInt8, UInt8)? {
        guard let a = probe.readByte(), let b = probe.readByte(), let c = probe.readByte(),
            let d = probe.readByte()
        else { return nil }
        return (a, b, c, d)
    }

    /// Returns the unmasked copy of `source`: `out[i] = source[i] ^ key[i % 4]` (RFC 6455 §5.3).
    ///
    /// One pass, 16 octets at a time via `SIMD16<UInt8>` — the 4-octet key repeated four times is
    /// phase-aligned (16 % 4 == 0), so each vector XOR applies the correct key byte to every lane; a
    /// scalar loop finishes the final < 16 octets. Fused with the slice copy, so the payload is
    /// touched once instead of being copied and then re-scanned. (A `UInt64` SWAR variant measured
    /// equivalent — both are bounded by `loadUnaligned`/`storeBytes`, not the lane width.)
    private static func unmaskedCopy(
        of source: UnsafeRawBufferPointer,
        with key: (UInt8, UInt8, UInt8, UInt8)
    ) -> [UInt8] {
        let count = source.count
        let keyVector = SIMD16<UInt8>(
            key.0, key.1, key.2, key.3, key.0, key.1, key.2, key.3,
            key.0, key.1, key.2, key.3, key.0, key.1, key.2, key.3)
        return [UInt8](unsafeUninitializedCapacity: count) { destination, initialized in
            let raw = UnsafeMutableRawBufferPointer(destination)
            var index = 0
            while index + 16 <= count {
                let chunk = source.loadUnaligned(fromByteOffset: index, as: SIMD16<UInt8>.self)
                raw.storeBytes(of: chunk ^ keyVector, toByteOffset: index, as: SIMD16<UInt8>.self)
                index += 16
            }
            // Scalar tail (< 16 octets); index stays a multiple of 16, so the key phase holds.
            while index < count {
                let keyByte: UInt8
                switch index & 0x3 {
                    case 0: keyByte = key.0
                    case 1: keyByte = key.1
                    case 2: keyByte = key.2
                    default: keyByte = key.3
                }
                destination[index] = source[index] ^ keyByte
                index += 1
            }
            initialized = count
        }
    }
}
