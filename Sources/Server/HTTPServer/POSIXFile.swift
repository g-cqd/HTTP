//
//  POSIXFile.swift
//  HTTPServer
//
//  The `EINTR`-retrying POSIX file primitives the descriptor-anchored static-file path is built from
//  (``RootDirectory`` → ``OpenedDirectory`` → ``OpenedFile``). Confining every raw syscall here keeps
//  `while errno == EINTR` out of the responder and gives the open flags one definition: a lookup hop is
//  always `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`, so a symlink component is refused (CWE-59) and a FIFO or
//  device node can never park a serve task inside `open(2)`.
//
//  Standards: open()/openat()/fstat()/pread()/close()/fcntl() per POSIX.1-2017 (IEEE Std 1003.1-2017).
//

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// The `EINTR`-retrying POSIX file syscalls behind descriptor-anchored static file serving.
enum POSIXFile {
    /// The flags for every lookup hop: read-only, never follow a symlink, never block on the open.
    ///
    /// `O_NOFOLLOW` makes a symlink *at this component* fail with `ELOOP` (CWE-59) instead of silently
    /// redirecting the walk. `O_NONBLOCK` keeps `open(2)` from parking on a FIFO or a device node with no
    /// writer; POSIX.1-2017 §open defines it as having no effect on a regular file, so the descriptor
    /// later handed to `pread(2)` or `sendfile(2)` behaves exactly as one opened without it.
    static let lookupFlags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK

    /// ``lookupFlags`` plus `O_DIRECTORY`, for an intermediate component that must be a directory.
    static let directoryFlags = lookupFlags | O_DIRECTORY

    /// Opens `path` as a directory — the one lookup made by name; returns the descriptor or `-errno`.
    ///
    /// Deliberately follows symlinks in `path`: the operator names the root, so its own path is trusted.
    /// Every lookup after this one is anchored on the returned descriptor and follows nothing.
    static func openRoot(_ path: String) -> Int32 {
        retrying { open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC) }
    }

    /// Opens `name` inside the directory `parent`; returns the descriptor or `-errno`.
    static func openAt(_ parent: Int32, _ name: some StringProtocol, flags: Int32) -> Int32 {
        name.withCString { pointer in
            retrying { openat(parent, pointer, flags) }
        }
    }

    /// Duplicates `descriptor` with close-on-exec set; returns the copy or `-errno`.
    static func duplicate(_ descriptor: Int32) -> Int32 {
        retrying { fcntl(descriptor, F_DUPFD_CLOEXEC, 0) }
    }

    /// The `fstat(2)` of `descriptor`, or nil when it fails.
    static func status(of descriptor: Int32) -> stat? {
        var info = stat()
        let result = retrying { fstat(descriptor, &info) }
        return result >= 0 ? info : nil
    }

    /// Whether `name` in the directory `parent` is itself a symlink, without following it.
    ///
    /// Only used to disambiguate a failed hop: `O_DIRECTORY | O_NOFOLLOW` on a symlink reports `ENOTDIR`
    /// (the link itself is not a directory), which is indistinguishable from `/regular-file/deeper`.
    static func isSymlink(_ name: some StringProtocol, in parent: Int32) -> Bool {
        var info = stat()
        let result = name.withCString { pointer in
            retrying { fstatat(parent, pointer, &info, AT_SYMLINK_NOFOLLOW) }
        }
        return result >= 0 && info.st_mode & S_IFMT == S_IFLNK
    }

    /// The whole-second modification time of `status` (`st_mtimespec` on Darwin, `st_mtim` elsewhere).
    static func modificationTime(of status: stat) -> Int {
        #if canImport(Darwin)
            return Int(status.st_mtimespec.tv_sec)
        #else
            return Int(status.st_mtim.tv_sec)
        #endif
    }

    /// The sub-second part of the modification time of `status`, in nanoseconds.
    ///
    /// Zero on a filesystem that keeps no sub-second timestamp. POSIX.1-2017 defines the field as a
    /// `struct timespec`, so it always exists, but its resolution belongs to the *filesystem*: APFS
    /// and ext4 with large inodes record nanoseconds, while HFS+, ext3, FAT (two-second granularity),
    /// and many NFS/SMB mounts leave it zero. A caller must treat it as extra entropy, never as a
    /// promise that two writes are distinguishable.
    static func modificationNanoseconds(of status: stat) -> Int {
        #if canImport(Darwin)
            return Int(status.st_mtimespec.tv_nsec)
        #else
            return Int(status.st_mtim.tv_nsec)
        #endif
    }

    /// Whether `name` is one safe path component: non-empty, not `.`/`..`, no NUL, within `NAME_MAX`.
    ///
    /// Pre-validation, not a substitute for `O_NOFOLLOW`: it bounds the syscalls a crafted path can force
    /// and refuses the lexical traversal forms outright (CWE-22).
    static func isSafeComponent(_ name: some StringProtocol) -> Bool {
        guard !name.isEmpty, name != ".", name != ".." else {
            return false
        }
        let octets = name.utf8
        return octets.count <= Int(NAME_MAX) && !octets.contains(0)
    }

    /// Fills `buffer` from `descriptor` starting at `offset`, or returns false — fails closed.
    ///
    /// `pread(2)`, never `read(2)`, so a descriptor shared with a concurrent reader (a `sendfile(2)` on
    /// the same open file, say) never has its file offset disturbed.
    static func readExactly(
        _ descriptor: Int32,
        into buffer: UnsafeMutableRawBufferPointer,
        at offset: Int
    ) -> Bool {
        var filled = 0
        while filled < buffer.count {
            let read = read(
                descriptor,
                into: buffer,
                start: filled,
                count: buffer.count - filled,
                at: offset + filled
            )
            guard read > 0 else {
                return false  // 0 is EOF short of the promised length, -1 an I/O failure
            }
            filled += read
        }
        return true
    }

    /// One `pread(2)` of at most `count` octets at `offset` into `buffer` from `start`; -1 on failure.
    static func read(
        _ descriptor: Int32,
        into buffer: UnsafeMutableRawBufferPointer,
        start: Int,
        count: Int,
        at offset: Int
    ) -> Int {
        guard let base = buffer.baseAddress else {
            return -1
        }
        while true {
            let read = pread(descriptor, base + start, count, off_t(offset))
            if read >= 0 {
                return read
            }
            if errno != EINTR {
                return -1
            }
        }
    }

    /// Closes `descriptor` exactly once.
    ///
    /// Never retried on `EINTR`: POSIX leaves the descriptor state unspecified after an interrupted
    /// `close(2)` and both Darwin and Linux have already released it, so a retry could close a descriptor
    /// another task has since been handed (CWE-672 operation on a resource after expiration).
    static func release(_ descriptor: Int32) {
        guard descriptor >= 0 else {
            return
        }
        _ = close(descriptor)
    }

    /// Runs `call` until it stops failing with `EINTR`, mapping a genuine failure to `-errno`.
    private static func retrying(_ call: () -> Int32) -> Int32 {
        while true {
            let result = call()
            if result >= 0 {
                return result
            }
            let code = errno
            if code != EINTR {
                return code == 0 ? -EIO : -code
            }
        }
    }
}
