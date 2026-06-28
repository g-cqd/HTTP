//
//  Base64.swift
//  HTTPCore
//
//  RFC 4648 — the package's single base64 codec, covering both the standard (§4, `+`/`/`, padded) and
//  URL-safe (§5, `-`/`_`, unpadded) alphabets, decode and encode. Foundation-free and allocation-lean:
//  decode fills one pre-sized `[UInt8]`, encode fills one `String` buffer in place — no `+`/`/`
//  re-substitution, no `=` re-padding, no intermediate `Data`, no per-call alphabet table (the octet
//  ⇄ sextet mapping is arithmetic). `package` so JWT segments, session-cookie tags, RFC 8941 byte
//  sequences, Basic-auth credentials, and the WebSocket handshake key all share one implementation.
//

/// RFC 4648 base64 — standard (§4) and URL-safe (§5), decode and encode, Foundation-free.
package enum Base64 {
    /// Which RFC 4648 alphabet a value uses for sextets 62 and 63.
    package enum Alphabet: Sendable {
        /// RFC 4648 §4 — `A–Z a–z 0–9 + /`.
        case standard
        /// RFC 4648 §5 — `A–Z a–z 0–9 - _` (URL- and filename-safe).
        case urlSafe
    }

    /// Decodes the base64 octets of `string` in `alphabet`, or nil if malformed.
    package static func decode(_ string: String, alphabet: Alphabet, padded: Bool) -> [UInt8]? {
        decode(string.utf8, alphabet: alphabet, padded: padded)
    }

    /// Decodes `bytes` in `alphabet`, or nil if malformed.
    ///
    /// `padded` requires the standard `=`-padded, multiple-of-4 form (RFC 4648 §4); unpadded forbids `=`
    /// and rejects the impossible ≡1 (mod 4) length (§5). Strict either way: a non-alphabet octet, a
    /// misplaced `=`, or non-minimal trailing pad bits (§3.5) fail closed, so a value cannot be silently
    /// rewritten into an equivalent-but-different encoding.
    package static func decode(
        _ bytes: some Collection<UInt8>,
        alphabet: Alphabet,
        padded: Bool
    ) -> [UInt8]? {
        let length = bytes.count
        if padded {
            guard length % 4 == 0 else {
                return nil
            }
        }
        else {
            guard length % 4 != 1 else {
                return nil
            }
        }
        var output: [UInt8] = []
        output.reserveCapacity(length / 4 * 3 + (length % 4 == 0 ? 0 : length % 4 - 1))
        var accumulator: UInt32 = 0
        var bitsFilled = 0
        var sawPadding = false
        for byte in bytes {
            if byte == UInt8(ascii: "=") {
                // '=' is only in the padded alphabet.
                guard padded else {
                    return nil
                }
                sawPadding = true
                continue  // padding carries no bits; the length %4==0 guard already fixed the count
            }
            guard !sawPadding, let sextet = sextet(of: byte, alphabet) else {
                return nil  // a data octet after padding, or one outside the alphabet
            }
            accumulator = (accumulator << 6) | UInt32(sextet)
            bitsFilled += 6
            if bitsFilled >= 8 {
                bitsFilled -= 8
                output.append(UInt8(truncatingIfNeeded: accumulator >> UInt32(bitsFilled)))
                // Keep only the still-unconsumed low bits.
                accumulator &= (UInt32(1) << UInt32(bitsFilled)) - 1
            }
        }
        // A canonical encoding leaves only zero pad bits; any set leftover bit is non-minimal (§3.5).
        return accumulator == 0 ? output : nil
    }

    /// Encodes `bytes` in `alphabet`, appending `=` padding when `padded` (RFC 4648 §4/§5).
    ///
    /// Takes `some Collection<UInt8>`, so a caller passes a `String.UTF8View` (or any byte collection)
    /// straight in — no `Array(…)` copy. Fills one `String` buffer in place by streaming three input
    /// octets to four output characters: no intermediate `[UInt8]`/`Data`, and the alphabet is computed
    /// arithmetically rather than indexed out of an allocated table.
    package static func encode(
        _ bytes: some Collection<UInt8>,
        alphabet: Alphabet,
        padded: Bool
    ) -> String {
        let sixtyTwo: UInt8 = alphabet == .urlSafe ? UInt8(ascii: "-") : UInt8(ascii: "+")
        let sixtyThree: UInt8 = alphabet == .urlSafe ? UInt8(ascii: "_") : UInt8(ascii: "/")
        func character(_ sextet: UInt32) -> UInt8 {
            switch sextet {
                case 0 ..< 26:
                    return UInt8(sextet) &+ UInt8(ascii: "A")
                case 26 ..< 52:
                    return UInt8(sextet &- 26) &+ UInt8(ascii: "a")
                case 52 ..< 62:
                    return UInt8(sextet &- 52) &+ UInt8(ascii: "0")
                case 62:
                    return sixtyTwo
                default:
                    return sixtyThree  // 63
            }
        }
        let count = bytes.count
        let remainder = count % 3
        let pad = UInt8(ascii: "=")
        let encodedLength = count / 3 * 4 + (remainder == 0 ? 0 : (padded ? 4 : remainder + 1))
        return String(unsafeUninitializedCapacity: encodedLength) { buffer in
            var write = 0
            var accumulator: UInt32 = 0
            var have = 0
            for byte in bytes {
                accumulator = (accumulator << 8) | UInt32(byte)
                have += 1
                if have == 3 {
                    buffer[write] = character((accumulator >> 18) & 0x3F)
                    buffer[write + 1] = character((accumulator >> 12) & 0x3F)
                    buffer[write + 2] = character((accumulator >> 6) & 0x3F)
                    buffer[write + 3] = character(accumulator & 0x3F)
                    write += 4
                    accumulator = 0
                    have = 0
                }
            }
            if have == 1 {
                let chunk = accumulator << 16
                buffer[write] = character((chunk >> 18) & 0x3F)
                buffer[write + 1] = character((chunk >> 12) & 0x3F)
                write += 2
                if padded {
                    buffer[write] = pad
                    buffer[write + 1] = pad
                    write += 2
                }
            }
            else if have == 2 {
                let chunk = accumulator << 8
                buffer[write] = character((chunk >> 18) & 0x3F)
                buffer[write + 1] = character((chunk >> 12) & 0x3F)
                buffer[write + 2] = character((chunk >> 6) & 0x3F)
                write += 3
                if padded {
                    buffer[write] = pad
                    write += 1
                }
            }
            return write
        }
    }

    /// The 6-bit value of a base64 alphabet octet, or nil if it is outside `alphabet` (RFC 4648 §4/§5).
    private static func sextet(of byte: UInt8, _ alphabet: Alphabet) -> UInt8? {
        switch byte {
            case UInt8(ascii: "A") ... UInt8(ascii: "Z"):
                return byte - UInt8(ascii: "A")
            case UInt8(ascii: "a") ... UInt8(ascii: "z"):
                return byte - UInt8(ascii: "a") + 26
            case UInt8(ascii: "0") ... UInt8(ascii: "9"):
                return byte - UInt8(ascii: "0") + 52
            case UInt8(ascii: "+"):
                return alphabet == .standard ? 62 : nil
            case UInt8(ascii: "/"):
                return alphabet == .standard ? 63 : nil
            case UInt8(ascii: "-"):
                return alphabet == .urlSafe ? 62 : nil
            case UInt8(ascii: "_"):
                return alphabet == .urlSafe ? 63 : nil
            default:
                return nil
        }
    }
}
