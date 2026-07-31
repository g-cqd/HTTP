//
//  RootDirectory.swift
//  HTTPServer
//
//  The static-file root as a descriptor rather than a pathname, and the `openat(2)` walk that resolves a
//  request path under it. This replaces the "resolve symlinks, compare string prefixes, then open by
//  name" shape, which was a textbook time-of-check/time-of-use hole: a writer could swap a path component
//  between the containment check and the open and escape the root (CWE-367, CWE-59).
//
//  Standards: openat()/fstat() per POSIX.1-2017 (IEEE Std 1003.1-2017). CWE-22 path traversal,
//  CWE-59 link following, CWE-367 TOCTOU.
//

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// The static-file root: one descriptor, opened once, that every lookup is anchored on.
///
/// Invariants, all upheld by ``resolve(_:)``:
/// 1. The root descriptor is opened ONCE (`O_RDONLY | O_DIRECTORY | O_CLOEXEC`) and is the only anchor.
///    No lookup ever re-resolves the root by name, so replacing the root path after startup — renaming
///    it, or swapping it for a symlink — cannot redirect a lookup (CWE-367).
/// 2. Every component is opened with `openat(parent, name, O_NOFOLLOW | O_CLOEXEC)`. A symlink at ANY
///    component, the last one included, fails with `ELOOP` and is refused (CWE-59). Containment is
///    therefore *structural*: a descriptor reached only by non-symlink `openat` hops from the root is
///    inside the root by construction — no string comparison, and no window between check and open.
/// 3. Components are pre-validated — non-empty, not `.` or `..`, no NUL, each within `NAME_MAX`, and at
///    most ``maxDepth`` of them — so a crafted path cannot force thousands of syscalls (CWE-22, CWE-400).
/// 4. An intermediate component adds `O_DIRECTORY`; the final `fstat(2)` must report `S_IFREG` for a
///    file, so a FIFO or a device node is refused and a serve task can never park inside `open(2)`.
/// 5. Every descriptor handed out is owned by its ``OpenedFile``/``OpenedDirectory`` and closed exactly
///    once, in `deinit`.
final class RootDirectory: Sendable {
    /// The deepest path a lookup will walk — the bound on syscalls per request (invariant 3).
    static let maxDepth = 32

    /// What resolving a request path under the root reached.
    enum Resolution {
        /// A regular file, with the directory that reached it — the anchor for its sidecars.
        case file(OpenedFile, parent: OpenedDirectory)
        /// A directory.
        case directory(OpenedDirectory)
        /// Nothing is there (`ENOENT`/`ENOTDIR`) — a `404`.
        case missing
        /// A symlink, a permission denial, a non-regular file, or a malformed component — a `403`.
        case refused
        /// The host is out of descriptors or memory — a `500`, not the client's fault.
        case unavailable
    }

    private let descriptor: Int32

    /// Opens `path` as the root, or fails when it is not an existing, readable directory.
    ///
    /// This is the one and only lookup made by name, and the only one that follows symlinks: the operator
    /// names the root, so its own path is trusted. Everything afterwards hangs off this descriptor.
    init?(path: String) {
        let opened = POSIXFile.openRoot(path)
        guard opened >= 0 else {
            return nil
        }
        descriptor = opened
    }

    deinit {
        POSIXFile.release(descriptor)
    }

    /// Resolves `components` under the root, one `O_NOFOLLOW` `openat(2)` hop per component.
    ///
    /// The walk carries a descriptor, never a path: each hop opens the next name *relative to the
    /// descriptor the previous hop returned*, and the intermediate descriptors are released by ARC as the
    /// cursor advances. An empty list resolves to the root itself.
    func resolve(_ components: [Substring]) -> Resolution {
        guard components.count <= Self.maxDepth,
            components.allSatisfy({ POSIXFile.isSafeComponent($0) })
        else {
            return .refused
        }
        // A duplicate, so the walk's ARC-owned cursor never closes the root's own descriptor.
        let anchor = POSIXFile.duplicate(descriptor)
        guard anchor >= 0 else {
            return .unavailable
        }
        var parent = OpenedDirectory(descriptor: anchor)
        for name in components.dropLast() {
            let opened = POSIXFile.openAt(parent.descriptor, name, flags: POSIXFile.directoryFlags)
            guard opened >= 0 else {
                return Self.hopFailure(errno: -opened, name: name, in: parent)
            }
            // The previous hop's descriptor closes with its last reference, as the cursor advances.
            parent = OpenedDirectory(descriptor: opened)
        }
        guard let name = components.last else {
            return .directory(parent)
        }
        return Self.leaf(name, in: parent)
    }

    /// Opens the final component: a regular file, a directory, else refused (invariant 4).
    private static func leaf(_ name: Substring, in parent: OpenedDirectory) -> Resolution {
        let opened = POSIXFile.openAt(parent.descriptor, name, flags: POSIXFile.lookupFlags)
        guard opened >= 0 else {
            return failure(errno: -opened)
        }
        guard let status = POSIXFile.status(of: opened) else {
            POSIXFile.release(opened)
            return .unavailable
        }
        switch status.st_mode & S_IFMT {
            case S_IFREG:
                return .file(OpenedFile(descriptor: opened, status: status), parent: parent)
            case S_IFDIR:
                return .directory(OpenedDirectory(descriptor: opened))
            default:
                // A FIFO, socket, or device node. `O_NONBLOCK` kept the open from parking on it; the
                // descriptor is dropped here so no serve task ever sees it.
                POSIXFile.release(opened)
                return .refused
        }
    }

    /// Maps a failed intermediate hop, telling a refused symlink apart from a genuinely absent name.
    ///
    /// `O_DIRECTORY | O_NOFOLLOW` on a symlink reports `ENOTDIR` — the link itself is not a directory —
    /// which is indistinguishable from `/regular-file/deeper`. One `fstatat(AT_SYMLINK_NOFOLLOW)`, on the
    /// failure path only so the hot path keeps its single syscall per hop, separates them: a symlink
    /// component stays a `403` (CWE-59) while an absent path stays a `404`.
    private static func hopFailure(
        errno code: Int32,
        name: Substring,
        in parent: OpenedDirectory
    ) -> Resolution {
        guard code == ENOTDIR, POSIXFile.isSymlink(name, in: parent.descriptor) else {
            return failure(errno: code)
        }
        return .refused
    }

    /// Maps a failed `openat(2)` to a resolution: absent, refused, or a host resource failure.
    private static func failure(errno code: Int32) -> Resolution {
        switch code {
            case ENOENT, ENOTDIR:
                return .missing
            case EMFILE, ENFILE, ENOMEM:
                return .unavailable
            default:
                // ELOOP (a symlink component — invariant 2), EACCES/EPERM, ENAMETOOLONG, EOVERFLOW…
                return .refused
        }
    }
}
