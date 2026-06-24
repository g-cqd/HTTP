//
//  FieldValidation.swift
//  HTTPCore
//
//  RFC 9110 "HTTP Semantics" field-name / field-value grammar validation.
//  These checks are the first line of defense against header injection and request
//  smuggling, so they are intentionally strict and allocation-free.
//

/// Validators for the low-level grammar shared by all HTTP versions (RFC 9110).
///
/// All routines iterate a byte sequence exactly once (`O(n)` time, `O(1)` space) and never
/// recurse, so they are safe to run on adversarial input on the hot path.
public enum FieldValidation {
    /// Returns `true` iff `bytes` is a non-empty `token` per RFC 9110 §5.6.2.
    ///
    /// ```
    /// token          = 1*tchar
    /// tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
    ///                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
    ///                / DIGIT / ALPHA
    /// ```
    ///
    /// A field-name MUST be a token (RFC 9112 §5.1); rejecting non-tokens closes off whitespace,
    /// control characters, and separators that enable smuggling/injection.
    @inlinable
    public static func isToken(_ bytes: some Sequence<UInt8>) -> Bool {
        var sawByte = false
        for byte in bytes {
            sawByte = true
            guard isTokenByte(byte) else { return false }
        }
        return sawByte  // 1*tchar — at least one byte is required.
    }

    /// Returns `true` iff `byte` is a single `tchar` (RFC 9110 §5.6.2).
    ///
    /// Implemented as constant-time range/membership checks (no table allocation, no recursion).
    @inlinable
    public static func isTokenByte(_ byte: UInt8) -> Bool {
        // All bounds are hex; contiguous tchar runs are folded to ranges (each range was verified
        // to contain *only* tchars — e.g. 0x22 '"' and 0x28 '(' fall outside 0x23...0x27).
        //
        // NOTE: a precomputed 256-entry `[Bool]` lookup table was benchmarked here and was 2–3× SLOWER
        // (`isToken` 42→83 ns, `isValidFieldValue` 42→125 ns): every access to a Swift `static let`
        // pays a lazy-init access guard, which costs more per byte than this inlined, well-predicted
        // switch. The switch is the measured optimum — do not "optimize" it into a table.
        switch byte {
            case 0x30 ... 0x39,  // DIGIT 0-9
                0x41 ... 0x5A,  // ALPHA A-Z
                0x61 ... 0x7A,  // ALPHA a-z
                0x21,  // "!"
                0x23 ... 0x27,  // "#" "$" "%" "&" "'"
                0x2A ... 0x2B,  // "*" "+"
                0x2D ... 0x2E,  // "-" "."
                0x5E ... 0x60,  // "^" "_" "`"
                0x7C,  // "|"
                0x7E:  // "~"
                return true
            default:
                return false
        }
    }

    /// Returns `true` iff `bytes` is a legal `field-value` per RFC 9110 §5.5.
    ///
    /// ```
    /// field-value   = *field-content
    /// field-vchar   = VCHAR / obs-text          ; VCHAR = %x21-7E
    /// obs-text      = %x80-FF
    /// ```
    ///
    /// A legal field value contains only HTAB, SP, VCHAR, or obs-text. It MUST NOT contain CR,
    /// LF, or NUL: per RFC 9110 §5.5 a recipient rejects (we never silently replace) such bytes,
    /// which is the primary defense against header injection / response splitting (CWE-113). The
    /// empty value is legal (`*field-content`).
    ///
    /// - Note: leading/trailing whitespace trimming is a separate concern (RFC 9110 §5.5); this
    ///   routine validates byte legality only.
    @inlinable
    public static func isValidFieldValue(_ bytes: some Sequence<UInt8>) -> Bool {
        if let valid = bytes.withContiguousStorageIfAvailable(fieldValueBytesAreValid) {
            return valid
        }
        for byte in bytes where !isFieldValueByte(byte) {
            return false
        }
        return true
    }

    /// SWAR validation of a contiguous field-value buffer: eight octets per word, then a scalar tail.
    ///
    /// A field-value octet is invalid iff it is a control below SP other than HTAB (`< 0x20 && != 0x09`)
    /// or DEL (`0x7F`); obs-text (`0x80–0xFF`) is valid. The three sub-tests are the classic "bytes < n"
    /// and "bytes == n" high-bit tricks (Hacker's Delight / Bit Twiddling Hacks), combined per octet as
    /// `(< 0x20 & != 0x09) | == 0x7F`. Unlike a delimiter scan this always reads *every* octet, so the
    /// 8×-per-word saving compounds — the access pattern SWAR is built for.
    ///
    /// Measured (release, cool M3, median of 3): `core/FieldValidation/isValidFieldValue-long` (198 B)
    /// 500 → 417 ns (**−17%**); the 24 B short value stayed flat (417 → 416 ns). Adopted. (Contrast the
    /// short-delimiter `ByteReader.firstIndex`, where SWAR did NOT pay off — see its note.)
    @usableFromInline
    static func fieldValueBytesAreValid(_ buffer: UnsafeBufferPointer<UInt8>) -> Bool {
        guard let base = buffer.baseAddress else { return true }
        let count = buffer.count
        let ones: UInt64 = 0x0101_0101_0101_0101
        let highs: UInt64 = 0x8080_8080_8080_8080
        let belowSpace = ones &* 0x20
        let htab = ones &* 0x09
        let del = ones &* 0x7F
        var index = 0
        while index &+ 8 <= count {
            let word = UnsafeRawPointer(base + index).loadUnaligned(as: UInt64.self)
            let isControl = (word &- belowSpace) & ~word & highs  // octet < 0x20
            let isHTAB = ((word ^ htab) &- ones) & ~(word ^ htab) & highs  // octet == 0x09
            let isDEL = ((word ^ del) &- ones) & ~(word ^ del) & highs  // octet == 0x7F
            if ((isControl & ~isHTAB) | isDEL) != 0 { return false }
            index &+= 8
        }
        while index < count {
            if !isFieldValueByte(base[index]) { return false }
            index &+= 1
        }
        return true
    }

    /// Returns `true` iff `byte` may appear in a `field-value` (RFC 9110 §5.5).
    ///
    /// Allowed: HTAB (0x09), SP + VCHAR (0x20–0x7E), obs-text (0x80–0xFF).
    /// Rejected: NUL, CR, LF, every other C0 control, and DEL (0x7F).
    @inlinable
    public static func isFieldValueByte(_ byte: UInt8) -> Bool {
        switch byte {
            case 0x09,  // HTAB
                0x20 ... 0x7E,  // SP + VCHAR
                0x80 ... 0xFF:  // obs-text
                true
            default:  // NUL, CR, LF, other C0 controls, DEL
                false
        }
    }

    /// Returns `true` iff `byte` may appear in a request-target or in an HTTP/2 `:path` / `:authority`
    /// / `:scheme` pseudo-header: any octet that is **not** a control, SP, or DEL.
    ///
    /// Rejecting CR (0x0D), LF (0x0A), NUL (0x00), the other C0/C1 controls, SP (0x20), and DEL (0x7F)
    /// is the defense against request-line / header / log injection and response splitting
    /// (CWE-113 / CWE-117) when these values are reflected or logged (RFC 9112 §3.2, RFC 9113 §8.3.1).
    @inlinable
    public static func isRequestTargetByte(_ byte: UInt8) -> Bool {
        byte > 0x20 && byte != 0x7F
    }

    /// Returns `true` iff every byte of `bytes` satisfies ``isRequestTargetByte(_:)`` — no control,
    /// SP, or DEL octet.
    ///
    /// Iterates once (`O(n)` time, `O(1)` space), never recurses. The empty sequence returns `true`;
    /// callers enforce non-emptiness separately (e.g. `:path` MUST be non-empty).
    @inlinable
    public static func isRequestTargetValue(_ bytes: some Sequence<UInt8>) -> Bool {
        if let valid = bytes.withContiguousStorageIfAvailable(requestTargetBytesAreValid) {
            return valid
        }
        for byte in bytes where !isRequestTargetByte(byte) {
            return false
        }
        return true
    }

    /// SWAR validation of a contiguous request-target/pseudo-header buffer: eight octets per word.
    ///
    /// An octet is invalid iff it is a control or SP (`<= 0x20`) or DEL (`0x7F`); obs-text (`0x80–0xFF`)
    /// is valid. Same high-bit tricks as ``fieldValueBytesAreValid`` (Hacker's Delight / Bit Twiddling
    /// Hacks): `(word - ones*0x21) & ~word & highs` flags octet `<= 0x20`, the `== 0x7F` test flags DEL.
    /// This runs on every HTTP/2 `:scheme`/`:authority`/`:path`/`:protocol` value (`HTTP2RequestMapper`),
    /// and `:path`/`:authority` can be long — a full scan, exactly the access pattern SWAR pays off on.
    @usableFromInline
    static func requestTargetBytesAreValid(_ buffer: UnsafeBufferPointer<UInt8>) -> Bool {
        guard let base = buffer.baseAddress else { return true }
        let count = buffer.count
        let ones: UInt64 = 0x0101_0101_0101_0101
        let highs: UInt64 = 0x8080_8080_8080_8080
        let controlOrSpace = ones &* 0x21  // detect octet < 0x21, i.e. a control or SP (<= 0x20)
        let del = ones &* 0x7F
        var index = 0
        while index &+ 8 <= count {
            let word = UnsafeRawPointer(base + index).loadUnaligned(as: UInt64.self)
            let isControlOrSpace = (word &- controlOrSpace) & ~word & highs  // octet <= 0x20
            let isDEL = ((word ^ del) &- ones) & ~(word ^ del) & highs  // octet == 0x7F
            if (isControlOrSpace | isDEL) != 0 { return false }
            index &+= 8
        }
        while index < count {
            if !isRequestTargetByte(base[index]) { return false }
            index &+= 1
        }
        return true
    }
}
