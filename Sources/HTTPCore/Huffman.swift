//
//  Huffman.swift
//  HTTPCore
//
//  RFC 7541 §5.2 / Appendix B — the canonical HTTP Huffman code, shared by HPACK (HTTP/2) and QPACK
//  (HTTP/3). Encoding pads the final octet with the most-significant bits of the EOS code; decoding
//  is an iterative (no recursion) canonical-code walk that fails closed on the three §5.2 decoding
//  errors: the EOS symbol appearing in the input, padding longer than 7 bits, and padding that is
//  not all 1-bits.
//

/// An error decoding a Huffman-coded string (RFC 7541 §5.2).
public enum HuffmanError: Error, Sendable, Equatable {

    /// The encoded data decoded the `EOS` symbol, which MUST NOT appear in the input (§5.2).
    case eosInInput

    /// The trailing padding was longer than 7 bits, or was not the MSBs of `EOS` (all 1-bits) (§5.2).
    case invalidPadding

    /// The bit stream did not form any valid code within the maximum code length.
    case invalidCode
}

/// The canonical HTTP Huffman code (RFC 7541 Appendix B).
public enum Huffman {

    /// The end-of-string symbol — its code's high bits pad the final octet; it is never a literal.
    @usableFromInline
    static let eosSymbol: UInt16 = 256

    // MARK: Encoding

    /// The number of octets `input` would occupy Huffman-encoded (RFC 7541 §5.2).
    ///
    /// The encoder uses this to honor the rule that the Huffman form is emitted only when it is no
    /// longer than the literal.
    public static func encodedByteLength(of input: some Sequence<UInt8>) -> Int {
        var bits = 0
        for byte in input { bits += Int(lengths[Int(byte)]) }
        return (bits + 7) / 8
    }

    /// Huffman-encodes `input`, padding the final partial octet with the high bits of `EOS` (§5.2).
    public static func encode(_ input: some Sequence<UInt8>) -> [UInt8] {
        var output = [UInt8]()
        // Reserve up front so byte-at-a-time append doesn't pay repeated geometric re-grows. For the
        // ASCII-dominant header text we encode the Huffman form is ≤ the input size, so the input's
        // own count is a good single reservation (a `Sequence` with no count reserves nothing).
        output.reserveCapacity(input.underestimatedCount)
        encode(input, into: &output)
        return output
    }

    /// Huffman-encodes `input` straight into `output` (§5.2) — no throwaway array for callers (HPACK /
    /// QPACK string literals) that already hold a destination buffer.
    public static func encode(_ input: some Sequence<UInt8>, into output: inout [UInt8]) {
        var bitBuffer: UInt64 = 0
        var bitCount = 0
        for byte in input {
            bitBuffer = (bitBuffer << lengths[Int(byte)]) | UInt64(codes[Int(byte)])
            bitCount += Int(lengths[Int(byte)])
            while bitCount >= 8 {
                bitCount -= 8
                output.append(UInt8((bitBuffer >> bitCount) & 0xFF))
            }
            bitBuffer &= (UInt64(1) << bitCount) - 1  // keep only the undrained low bits
        }
        if bitCount > 0 {
            let padding = 8 - bitCount
            let lastOctet = (bitBuffer << padding) | ((UInt64(1) << padding) - 1)
            output.append(UInt8(lastOctet & 0xFF))
        }
    }

    // MARK: Decoding

    /// Huffman-decodes `input` into its literal octets (RFC 7541 §5.2).
    ///
    /// Walks the bit stream one bit at a time over the canonical code (no recursion), emitting a
    /// symbol as soon as the accumulated bits match a code of the current length. Fails closed on the
    /// three §5.2 decoding errors.
    public static func decode(_ input: RawSpan) throws(HuffmanError) -> [UInt8] {
        var caught: (any Error)?
        let output = [UInt8](unsafeUninitializedCapacity: decodedUpperBound(of: input)) {
            buffer, count in
            do { count = try decode(input, into: buffer) } catch { caught = error }
        }
        if let caught { throw (caught as? HuffmanError) ?? .invalidCode }
        return output
    }

    /// Huffman-decodes `input` straight into a `String` (RFC 7541 §5.2).
    ///
    /// Repairs non-UTF-8 octets exactly as `String(decoding:as:)` does. The bit-walk runs into a
    /// stack scratch buffer, so a typical small value costs a single heap allocation — the `String` —
    /// with no throwaway intermediate `[UInt8]`. This is the HPACK decoder's hot path.
    public static func decodeString(_ input: RawSpan) throws(HuffmanError) -> String {
        var decoded: String?
        var caught: (any Error)?
        withUnsafeTemporaryAllocation(of: UInt8.self, capacity: decodedUpperBound(of: input)) {
            buffer in
            do {
                let written = try decode(input, into: buffer)
                decoded = String(
                    decoding: UnsafeBufferPointer(rebasing: buffer[..<written]), as: UTF8.self)
            } catch {
                caught = error
            }
        }
        if let caught { throw (caught as? HuffmanError) ?? .invalidCode }
        return decoded ?? ""
    }

    /// The maximum octets `input` can decode to (shortest code is 5 bits → ≤ ⌈input·8 / 5⌉ symbols).
    @usableFromInline
    static func decodedUpperBound(of input: RawSpan) -> Int {
        max(1, input.byteCount * 8 / 5 + 1)
    }

    /// Decodes `input` into `buffer`, returning the number of octets written.
    ///
    /// Drives the nibble FSM (``nibbleDFA``): two table lookups per octet, each consuming four bits
    /// and emitting at most one symbol. `buffer` MUST be at least ``decodedUpperBound(of:)`` octets;
    /// throws on the three §5.2 errors. Allocation-free — the caller owns the buffer.
    static func decode(
        _ input: RawSpan, into buffer: UnsafeMutableBufferPointer<UInt8>
    ) throws(HuffmanError) -> Int {
        let dfa = nibbleDFA  // read the lazy `static let` once, not per nibble
        let transitions = dfa.transitions
        let emit = emitFlag
        let eos = eosFlag
        let errorFlags = eos | invalidFlag
        var state = 0
        var written = 0
        var index = 0
        while index < input.byteCount {
            let octet = input.unsafeLoad(fromByteOffset: index, as: UInt8.self)
            var transition = transitions[state * 16 + Int(octet >> 4)]  // high nibble
            if transition.flags & errorFlags != 0 {
                throw transition.flags & eos != 0 ? .eosInInput : .invalidCode
            }
            if transition.flags & emit != 0 {
                buffer[written] = transition.symbol
                written += 1
            }
            state = Int(transition.nextState)
            transition = transitions[state * 16 + Int(octet & 0x0F)]  // low nibble
            if transition.flags & errorFlags != 0 {
                throw transition.flags & eos != 0 ? .eosInInput : .invalidCode
            }
            if transition.flags & emit != 0 {
                buffer[written] = transition.symbol
                written += 1
            }
            state = Int(transition.nextState)
            index += 1
        }
        // The stream must end at a symbol boundary or on valid EOS-prefix padding (RFC 7541 §5.2).
        guard dfa.paddingValid[state] else { throw .invalidPadding }
        return written
    }
}
