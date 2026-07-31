//
//  FileValidator.swift
//  HTTPServer
//
//  The cache validator ``FileResponder`` puts on a static file (RFC 9110 §8.8). It is derived purely
//  from the descriptor's own `fstat(2)` — no second lookup, and no read of the content — which is what
//  makes it cheap enough for the `sendfile(2)` path but also what caps how much it can promise.
//
//  Why the tag is WEAK. RFC 9110 §8.8.1 defines a strong validator as one that "changes value whenever
//  a change occurs to the representation data that would be observable in the content", and then names
//  this exact failure: "a representation's modification time, if defined with only one-second
//  resolution, might be a weak validator if it is possible for the representation to be modified twice
//  during a single second and retrieved between those modifications". Size plus whole-second mtime is
//  precisely that, so a same-size rewrite inside one second used to hand two different bodies the same
//  *strong* tag — a cache would then reuse the stale body forever, and `If-Match`/`If-Range` would
//  authorize an update or a range against bytes that are no longer there. The tag is now `W/`-prefixed,
//  which is the honest statement of what descriptor metadata can support.
//
//  Why not a content digest. A strong tag needs the bytes (§8.8.1 suggests "a collision-resistant hash
//  of the representation data"), which means reading every octet of every file on every response — the
//  exact copy the descriptor-anchored `sendfile(2)` path exists to avoid — or a cache that has to be
//  invalidated correctly, i.e. the very problem being solved. That trade belongs to a deployment that
//  actually needs `If-Match` on static files, not to the default path.
//
//  What the fingerprint mixes, and its portability limits:
//  - `st_size` and the whole-second mtime — portable everywhere, and the weakest part.
//  - the nanoseconds component of the mtime — POSIX.1-2017 always defines the field, but its
//    resolution is the filesystem's: APFS and ext4 with large inodes record nanoseconds, HFS+, ext3,
//    FAT (two-second granularity) and many NFS/SMB mounts record zero. Where it is zero the tag
//    degrades to exactly what it was before, which is why weakness is asserted unconditionally rather
//    than inferred from the mount.
//  - `st_dev` + `st_ino` — these separate two *different* same-size files stamped to the same second.
//    `st_ino` is unique only within a device, hence the pair. `st_dev` is not stable across a reboot
//    or a remount (notably NFS), so a tag can change without the content changing; for a weak
//    validator that costs one revalidation, which is another reason it must not claim to be strong.
//    Both are hashed, never emitted: Apache's `FileETag INode` leaked inode numbers to clients
//    (CVE-2003-1418) and also made two replicas of the same file disagree.
//
//  The hash is FNV-1a (64-bit), not `Hasher`: `Hasher` is seeded per process, so restarting the server
//  or adding a replica would invalidate every client's cached copy.
//

/// Derives the `ETag` ``FileResponder`` sends for an open file (RFC 9110 §8.8).
enum FileValidator {
    /// The FNV-1a 64-bit offset basis.
    private static let offsetBasis: UInt64 = 0xcbf2_9ce4_8422_2325

    /// The FNV-1a 64-bit prime.
    private static let prime: UInt64 = 0x0000_0100_0000_01b3

    /// The weak entity-tag for `file` under the optional content `encoding`.
    ///
    /// `W/"<hex size>-<hex fingerprint>[-<coding>]"`. The coding is part of the tag because a content
    /// coding produces a different representation of the same resource (RFC 9110 §8.8.3), and a cache
    /// keyed on `Vary: Accept-Encoding` must be able to tell the two apart. Weak per §8.8.1 — see the
    /// file comment for exactly what descriptor metadata can and cannot promise.
    static func entityTag(for file: OpenedFile, encoding: String?) -> String {
        let base = "\(String(file.size, radix: 16))-\(String(fingerprint(of: file), radix: 16))"
        guard let encoding else {
            return "W/\"\(base)\""
        }
        return "W/\"\(base)-\(encoding)\""
    }

    /// The FNV-1a digest of every identity field the `fstat(2)` offers.
    private static func fingerprint(of file: OpenedFile) -> UInt64 {
        var hash = offsetBasis
        hash = mixing(hash, file.deviceIdentifier)
        hash = mixing(hash, file.inode)
        hash = mixing(hash, UInt64(bitPattern: Int64(file.size)))
        hash = mixing(hash, UInt64(bitPattern: Int64(file.modifiedAt)))
        hash = mixing(hash, UInt64(bitPattern: Int64(file.modifiedNanoseconds)))
        return hash
    }

    /// `hash` advanced by the eight octets of `value`, least significant first.
    private static func mixing(_ hash: UInt64, _ value: UInt64) -> UInt64 {
        var hash = hash
        var remaining = value
        for _ in 0 ..< 8 {
            hash ^= remaining & 0xFF
            hash &*= prime
            remaining >>= 8
        }
        return hash
    }
}
