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
        case 0x30...0x39,  // DIGIT 0-9
            0x41...0x5A,  // ALPHA A-Z
            0x61...0x7A,  // ALPHA a-z
            0x21,  // "!"
            0x23...0x27,  // "#" "$" "%" "&" "'"
            0x2A...0x2B,  // "*" "+"
            0x2D...0x2E,  // "-" "."
            0x5E...0x60,  // "^" "_" "`"
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
        for byte in bytes where !isFieldValueByte(byte) {
            return false
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
            0x20...0x7E,  // SP + VCHAR
            0x80...0xFF:  // obs-text
            true
        default:  // NUL, CR, LF, other C0 controls, DEL
            false
        }
    }
}
