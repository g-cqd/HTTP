//
//  Base64.swift
//  HTTPCore
//
//  RFC 4648 — thin facade over `AemiKernel.Base64` (backed by `AemiKernels` NEON/SSSE3 block
//  kernels), covering both the standard (§4, `+`/`/`, padded) and URL-safe (§5, `-`/`_`, unpadded)
//  alphabets, decode and encode. Foundation-free, canonical trailing-bit validation (§3.5).
//

internal import AemiKernel

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

    /// Decodes `bytes` in `alphabet`, or nil if malformed (RFC 4648 §3.5/§4/§5).
    ///
    /// Delegates to `AemiKernel.Base64` (SIMD-accelerated via `AemiKernels`) with canonical trailing
    /// bits and strict padding policy matching RFC 4648 §3.5.
    package static func decode(
        _ bytes: some Collection<UInt8>,
        alphabet: Alphabet,
        padded: Bool
    ) -> [UInt8]? {
        try? AemiKernel.Base64.decode(bytes, options: options(alphabet: alphabet, padded: padded))
    }

    /// Encodes `bytes` in `alphabet`, appending `=` padding when `padded` (RFC 4648 §4/§5).
    package static func encode(
        _ bytes: some Collection<UInt8>,
        alphabet: Alphabet,
        padded: Bool
    ) -> String {
        AemiKernel.Base64.encodedString(bytes, options: options(alphabet: alphabet, padded: padded))
    }

    private static func options(
        alphabet: Alphabet,
        padded: Bool
    ) -> AemiKernel.Base64.Options {
        switch (alphabet, padded) {
            case (.standard, true):
                return .strict
            case (.urlSafe, true):
                return .urlSafe
            case (.urlSafe, false):
                return .urlSafeNoPadding
            case (.standard, false):
                return AemiKernel.Base64.Options(
                    alphabet: .standard,
                    padding: .forbidden,
                    trailingBits: .canonical,
                    whitespace: .reject
                )
        }
    }
}
