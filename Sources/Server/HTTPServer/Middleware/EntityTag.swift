//
//  EntityTag.swift
//  HTTPServer
//
//  RFC 9110 §8.8.3 — a body-derived entity-tag, shared by the conditional-request, Range, and static-file
//  layers so all compute and compare the *same* validator (a client's `If-Range`/`If-None-Match` tag,
//  minted from an earlier response, must match regardless of which layer checks it). This type also
//  centralizes the §13.1 tag-comparison rules so the conditional middleware and the file responder share
//  one implementation.
//
//  Why the tag is WEAK (REG-4b). It is `W/"<hex size>-<hex CRC-32>"`, and the `W/` is the whole point.
//  §8.8.1 defines a strong validator as one that "changes value whenever a change occurs to the
//  representation data that would be observable in the content", and suggests "a collision-resistant
//  hash of the representation data". CRC-32 (RFC 1952 §8) is neither: it is a 32-bit error-detecting
//  code, affine over GF(2), so a same-length collision is *constructed* rather than stumbled upon — a
//  birthday search over an 8-octet padding field finds one in a fraction of a second (CWE-328, use of a
//  weak hash). `EntityTagCollisionTests` carries such a pair, and it is the proof: two 33-octet bodies,
//  one saying `"role":"user"` and one `"role":"admin"`, that shared a byte-identical *strong* tag.
//
//  What the weakness costs, and why that is the correct trade. `If-Match` (§13.1.1) and `If-Range`
//  (§13.1.5) both use the STRONG comparison function, so a `W/` tag can no longer satisfy either: an
//  `If-Match` now answers `412`, and an `If-Range` serves the whole representation instead of a `206`.
//  That is precisely the promise being withdrawn — under the old tag, a client could authorize an
//  update against a representation it had never seen, or splice a range out of a *different* body into
//  its cached copy. `If-None-Match` / `304` revalidation, which is what a cache validator is actually
//  for, uses the WEAK comparison function (§13.1.2) and is unaffected.
//
//  Why not a collision-resistant digest instead. A strong tag would mean SHA-256 over every response
//  body on the 200k-rps path, charged to every client, to serve a precondition this middleware cannot
//  honor anyway: it decorates a *response*, so it runs after the handler has already acted, and its own
//  documented scope is GET/HEAD — an `If-Match` on the PUT/DELETE that `If-Match` exists for must be
//  enforced by the handler before it mutates state. ``FileValidator`` reached the same conclusion for
//  static files from the other direction (it cannot read the bytes at all); both now say `W/`.
//

internal import Foundation
internal import HTTPCore

/// Derives and compares entity-tags for representation bodies (RFC 9110 §8.8.3 / §13.1).
enum EntityTag {
    /// The **weak** entity-tag for `body`: `W/"<hex size>-<hex CRC-32>"`.
    ///
    /// Weak per RFC 9110 §8.8.1 because CRC-32 is not collision-resistant, so the tag cannot promise
    /// to change whenever the representation's octets do — see the file comment for the constructed
    /// collision that makes that concrete, and for what the `W/` withdraws.
    static func crc(for body: [UInt8]) -> String {
        "W/\"\(String(body.count, radix: 16))-\(String(CRC32.checksum(body), radix: 16))\""
    }

    /// An entity-tag's opaque value — the tag with any weak `W/` prefix removed (RFC 9110 §8.8.3).
    static func opaque(_ tag: some StringProtocol) -> String {
        tag.hasPrefix("W/") ? String(tag.dropFirst(2)) : String(tag)
    }

    /// Whether any entry across `candidates` (comma-separated `If-None-Match` field values) matches
    /// `etag` under weak comparison (RFC 9110 §13.1.2); `*` matches any current representation.
    static func weakMatches(_ candidates: [String], _ etag: String) -> Bool {
        let target = opaque(etag)
        for value in candidates {
            for element in value.split(separator: ",") {
                let candidate = element.trimmingCharacters(in: .whitespaces)
                if candidate == "*" || opaque(candidate) == target {
                    return true
                }
            }
        }
        return false
    }

    /// Whether any entry across `candidates` (comma-separated `If-Match` field values) matches `etag`
    /// under strong comparison (RFC 9110 §13.1.1) — a weak (`W/`) tag on either side never matches.
    ///
    /// `*` is checked *before* the weakness of `etag`, because it is not an entity-tag comparison at
    /// all: §13.1.1 makes `*` ask only whether the origin server has a current representation, so a
    /// weak validator neither helps nor hinders it. Testing it afterwards — as this did while the tag
    /// was strong and the distinction could not be observed — would turn every `If-Match: *` into a
    /// spurious `412` the moment the tag became weak.
    static func strongMatches(_ candidates: [String], _ etag: String) -> Bool {
        let isStrong = !etag.hasPrefix("W/")
        for value in candidates {
            for element in value.split(separator: ",") {
                let candidate = element.trimmingCharacters(in: .whitespaces)
                if candidate == "*" {
                    return true
                }
                if isStrong, !candidate.hasPrefix("W/"), candidate == etag {
                    return true
                }
            }
        }
        return false
    }
}
