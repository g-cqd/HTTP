//
//  MultipartBoundary.swift
//  HTTPCore
//
//  RFC 2046 §5.1.1 — the validated `multipart` boundary and the delimiter it generates:
//
//      boundary      := 0*69<bchars> bcharsnospace
//      bchars        := bcharsnospace / " "
//      bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / "," / "-" / "." / "/" / ":"
//                       / "=" / "?"
//
//  So a boundary is 1–70 characters from a closed ASCII set and may never end in a space. Validating
//  it before any scanning is not cosmetic: the boundary is attacker-controlled needle data (it arrives
//  in the request's `Content-Type`), and an unbounded one is copied into every delimiter comparison
//  (CWE-1284, improper validation of a specified quantity in input). A boundary containing CR or LF
//  would additionally let a peer make the delimiter needle self-overlap, which the parts scanner
//  relies on being impossible.
//

/// A validated RFC 2046 §5.1.1 `multipart` boundary and the delimiter that separates its parts.
///
/// The delimiter is the boundary's real wire form: `CRLF "--" boundary`. Holding it pre-rendered lets
/// the scanner compare against one contiguous needle instead of re-deriving the CRLF and dashes.
struct MultipartBoundary {
    /// The longest boundary RFC 2046 §5.1.1 permits (`0*69<bchars>` plus one `bcharsnospace`).
    static let maxLength = 70

    /// `CRLF "--" boundary` — the delimiter that precedes every part (RFC 2046 §5.1.1).
    let delimiter: [UInt8]

    /// The Knuth-Morris-Pratt failure function over ``delimiter``.
    ///
    /// `failure[length]` is the length of the longest proper prefix of `delimiter[0..<length]` that is
    /// also a suffix of it, so a matcher that mismatches after `length` bytes can resume at
    /// `failure[length]` without rewinding the text. It has `delimiter.count + 1` entries; values fit
    /// in a byte because the delimiter is at most 74 bytes.
    ///
    /// For any boundary this type accepts the table is entirely zero — `bchars` excludes CR, so the
    /// delimiter's leading CR cannot recur and the needle has no proper border. It is still computed
    /// rather than assumed: the matcher's linearity then rests on the algorithm, not on the character
    /// set staying exactly as it is today.
    let failure: [UInt8]

    /// The number of bytes the delimiter's leading CRLF occupies, which the opening `dash-boundary`
    /// (the first delimiter in a body without a preamble) does not carry.
    static let crlfCount = 2

    /// Creates the delimiter for `boundary`, or nil when `boundary` is outside the RFC 2046 §5.1.1
    /// grammar (empty, over 70 characters, space-terminated, or containing a non-`bchars` byte).
    init?(_ boundary: String) {
        let prefixCount = Self.crlfCount + 2  // CRLF "--"
        var bytes: [UInt8] = [0x0D, 0x0A, 0x2D, 0x2D]
        bytes.reserveCapacity(prefixCount + Self.maxLength)
        var last: UInt8 = 0
        for byte in boundary.utf8 {
            guard Self.isBoundaryByte(byte), bytes.count < prefixCount + Self.maxLength else {
                return nil
            }
            bytes.append(byte)
            last = byte
        }
        // `0*69<bchars> bcharsnospace`: at least one character, and the last is never a space.
        guard bytes.count > prefixCount, last != 0x20 else {
            return nil
        }
        self.delimiter = bytes
        self.failure = Self.failureTable(bytes)
    }

    /// The Knuth-Morris-Pratt failure function over `needle`, with `needle.count + 1` entries.
    ///
    /// Built in `O(needle.count)` by the standard construction: the table is its own matcher, extending
    /// the current border when the next byte agrees and retreating through the already-built prefix
    /// when it does not.
    static func failureTable(_ needle: [UInt8]) -> [UInt8] {
        var table = [UInt8](repeating: 0, count: needle.count + 1)
        var border = 0
        for index in 1 ..< max(needle.count, 1) {
            while border > 0, needle[index] != needle[border] {
                border = Int(table[border])
            }
            if needle[index] == needle[border] {
                border += 1
            }
            table[index + 1] = UInt8(truncatingIfNeeded: border)
        }
        return table
    }

    /// Whether `byte` is an RFC 2046 §5.1.1 `bchars` character (`bcharsnospace` plus SP).
    ///
    /// Deliberately a closed set rather than "printable ASCII": the exclusions are what make a
    /// delimiter unambiguous — no CR, no LF, no `"` (which would break the quoted `boundary=`
    /// parameter), no `;` (which would break the parameter list itself).
    static func isBoundaryByte(_ byte: UInt8) -> Bool {
        switch byte {
            case 0x30 ... 0x39, 0x41 ... 0x5A, 0x61 ... 0x7A:  // DIGIT / ALPHA
                true
            case 0x27, 0x28, 0x29, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F:  // ' ( ) + , - . /
                true
            case 0x3A, 0x3D, 0x3F, 0x5F, 0x20:  // : = ? _ SP
                true
            default:
                false
        }
    }
}
