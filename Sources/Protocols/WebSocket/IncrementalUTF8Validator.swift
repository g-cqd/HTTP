//
//  IncrementalUTF8Validator.swift
//  WebSocket
//
//  RFC 3629 / Unicode Table 3-7 — an incremental UTF-8 well-formedness check. Unlike a one-shot scan
//  it carries the state of a partially-seen multi-byte scalar across calls, so a fragmented text
//  message (RFC 6455 §5.4) is validated as each fragment arrives — rejecting invalid text at the first
//  bad octet rather than buffering the whole (up to `maxMessageSize`) message first (§8.1).
//  Allocation-free; a single forward pass; no recursion.
//

import ADFKernels

/// An incremental UTF-8 validator (RFC 3629): feed bytes across calls, then check ``isComplete``.
struct IncrementalUTF8Validator {
    /// Continuation octets still expected to finish the current scalar (0 when between scalars).
    private var pending = 0
    /// The legal range for the *next* continuation octet — narrowed on the first one to encode the
    /// overlong / surrogate / max-code-point exclusions, then `0x80…0xBF` for the rest.
    private var nextLow: UInt8 = 0x80
    private var nextHigh: UInt8 = 0xBF

    /// Whether no partial multi-byte scalar is outstanding — required at the end of a text message.
    var isComplete: Bool { pending == 0 }

    /// Consumes `bytes`, returning `false` at the first octet that cannot extend well-formed UTF-8.
    ///
    /// A `false` is terminal: the message is malformed. A `true` only means "well-formed so far" — the
    /// caller must still check ``isComplete`` once the message ends, to reject a trailing partial scalar.
    mutating func consume(_ bytes: some Sequence<UInt8>) -> Bool {
        // Contiguous input takes the SIMD ASCII-skip fast path; anything else uses the scalar loop.
        // Both carry the same cross-call state (`pending`/`nextLow`/`nextHigh`) and are result-identical.
        if let result = bytes.withContiguousStorageIfAvailable({ buffer in consumeContiguous(buffer) }) {
            return result
        }
        return consumeScalar(bytes)
    }

    /// Contiguous fast path: while between scalars, a runtime-dispatched SIMD scan skips the ASCII run
    /// to the first non-ASCII byte (long text frames are mostly ASCII, RFC 6455 §5.6), then each
    /// multi-byte scalar is range-checked per octet exactly as ``consumeScalar(_:)`` does.
    private mutating func consumeContiguous(_ buffer: UnsafeBufferPointer<UInt8>) -> Bool {
        guard let base = buffer.baseAddress else { return true }
        let count = buffer.count
        var index = 0
        while index < count {
            if pending == 0 {
                if buffer[index] < 0x80 {
                    index += ADFKernels.firstNonASCII(base: base + index, count: count - index)
                    if index >= count { break }
                }
                guard let sequence = Self.sequence(forLead: buffer[index]) else {
                    return false
                }
                pending = sequence.length - 1
                nextLow = sequence.secondLow
                nextHigh = sequence.secondHigh
                index += 1
            } else {
                let byte = buffer[index]
                guard byte >= nextLow, byte <= nextHigh else {
                    return false
                }
                pending -= 1
                nextLow = 0x80  // subsequent continuation octets take the full range
                nextHigh = 0xBF
                index += 1
            }
        }
        return true
    }

    /// Scalar fallback for non-contiguous sequences (the reference behavior).
    private mutating func consumeScalar(_ bytes: some Sequence<UInt8>) -> Bool {
        for byte in bytes {
            if pending == 0 {
                if byte < 0x80 {
                    continue  // ASCII — the common case
                }
                guard let sequence = Self.sequence(forLead: byte) else {
                    return false
                }
                pending = sequence.length - 1
                nextLow = sequence.secondLow
                nextHigh = sequence.secondHigh
            }
            else {
                guard byte >= nextLow, byte <= nextHigh else {
                    return false
                }
                pending -= 1
                nextLow = 0x80  // subsequent continuation octets take the full range
                nextHigh = 0xBF
            }
        }
        return true
    }

    /// For a non-ASCII lead octet (RFC 3629): the scalar length and the legal range for the *first*
    /// continuation octet — which encodes the overlong / surrogate / > U+10FFFF exclusions — or nil for
    /// `0x80…0xC1` / `0xF5…0xFF`, which can never lead a sequence.
    private static func sequence(
        forLead lead: UInt8
    ) -> (length: Int, secondLow: UInt8, secondHigh: UInt8)? {
        switch lead {
            case 0xC2 ... 0xDF:
                (2, 0x80, 0xBF)
            case 0xE0:
                (3, 0xA0, 0xBF)  // reject overlong
            case 0xE1 ... 0xEC:
                (3, 0x80, 0xBF)
            case 0xED:
                (3, 0x80, 0x9F)  // reject surrogates
            case 0xEE ... 0xEF:
                (3, 0x80, 0xBF)
            case 0xF0:
                (4, 0x90, 0xBF)  // reject overlong
            case 0xF1 ... 0xF3:
                (4, 0x80, 0xBF)
            case 0xF4:
                (4, 0x80, 0x8F)  // reject > U+10FFFF
            default:
                nil
        }
    }
}
