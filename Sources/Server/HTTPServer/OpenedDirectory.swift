//
//  OpenedDirectory.swift
//  HTTPServer
//
//  An open, verified directory reached only by `O_NOFOLLOW` `openat(2)` hops from a ``RootDirectory``.
//  It is the anchor for everything opened *next to* the file it reached — the `.br`/`.gz` sidecars, a
//  directory's `index.html`, an autoindex listing — so none of those lookups re-traverses the path by
//  name and none of them can be redirected by a concurrent rename (CWE-367).
//

/// An open, verified directory under the root — the anchor for a sibling or child lookup.
///
/// Owns its descriptor and closes it exactly once, in `deinit`.
final class OpenedDirectory: Sendable {
    /// The verified descriptor: read-only, close-on-exec, never reached through a symlink.
    let descriptor: Int32

    /// Takes ownership of `descriptor`, which must already have been shown to be a directory.
    init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit {
        POSIXFile.release(descriptor)
    }

    /// Opens the regular file `name` in this directory, or nil.
    ///
    /// Returns nil for an absent name, a symlink (`O_NOFOLLOW` → `ELOOP`, CWE-59), anything that is not a
    /// regular file, and any `name` that is not one safe path component. The callers — sidecar
    /// negotiation and `index.html` — treat every one of those the same way: skip it.
    func openFile(named name: some StringProtocol) -> OpenedFile? {
        guard POSIXFile.isSafeComponent(name) else {
            return nil
        }
        let opened = POSIXFile.openAt(descriptor, name, flags: POSIXFile.lookupFlags)
        guard opened >= 0 else {
            return nil
        }
        return OpenedFile.adopting(opened)
    }
}
