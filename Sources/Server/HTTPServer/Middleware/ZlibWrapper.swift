//
//  ZlibWrapper.swift
//  HTTPServer
//
//  RFC 1950 — the 2-octet CMF/FLG header and 4-octet Adler-32 trailer some `Content-Encoding: deflate`
//  senders wrap around a DEFLATE stream. Apple's Compression framework decodes RFC 1951 only, so the
//  wrapper has to be handled here; the previous code handled it by *stripping* the header and trailer
//  and decoding what was left, which is not the same thing. That accepted a stream whose declared
//  compression method was not DEFLATE, whose header check bits were nonsense, or whose payload had
//  been corrupted in transit — the trailer exists precisely to catch the last of those, and discarding
//  it discards the only integrity check a zlib-wrapped body has.
//
//  Parsing is pure byte arithmetic with no platform dependency, so it stays outside the
//  Compression-framework file it serves.
//

internal import HTTPCore

/// A parsed RFC 1950 zlib stream: the DEFLATE payload plus the Adler-32 the sender claims for it.
struct ZlibWrapper {
    /// The 2-octet header and 4-octet trailer that bracket the payload (RFC 1950 §2.2).
    private static let overhead = 6

    /// The RFC 1951 DEFLATE payload between the header and the trailer.
    let payload: ArraySlice<UInt8>

    /// The trailer's Adler-32 of the *uncompressed* data, big-endian on the wire (RFC 1950 §2.2).
    let declaredChecksum: UInt32

    /// Parses `input` as a zlib stream, or nil when its header is not a valid one (RFC 1950 §2.2).
    ///
    /// Being nil is not "reject the body": the caller falls back to raw DEFLATE, which is the far more
    /// common HTTP spelling of `deflate`. The header is self-identifying enough for that to be a safe
    /// discrimination — CM must be 8, and the 16-bit header must be a multiple of 31 — so a raw stream
    /// is misread as wrapped only about once in five hundred, and the decode then fails and falls back
    /// anyway.
    init?(_ input: [UInt8]) {
        guard input.count > Self.overhead else {
            return nil
        }
        let cmf = input[0]
        let flg = input[1]
        // CM must be 8 (DEFLATE) with a window of at most 32 KiB (CINFO <= 7). FDICT announces a
        // preset dictionary the sender assumes we hold; we do not, so a stream requesting one is
        // refused rather than decoded against the wrong dictionary.
        guard cmf & 0x0F == 8, cmf >> 4 <= 7, flg & 0x20 == 0 else {
            return nil
        }
        // FCHECK: the check bits are chosen so the big-endian header word is a multiple of 31.
        guard (UInt16(cmf) << 8 | UInt16(flg)) % 31 == 0 else {
            return nil
        }
        let end = input.count - 4
        payload = input[2 ..< end]
        declaredChecksum =
            UInt32(input[end]) << 24 | UInt32(input[end + 1]) << 16
            | UInt32(input[end + 2]) << 8 | UInt32(input[end + 3])
    }

    /// Whether the trailer's Adler-32 matches `output` (RFC 1950 §2.2, §9).
    func checksumMatches(_ output: [UInt8]) -> Bool {
        declaredChecksum == Adler32.checksum(output)
    }
}
