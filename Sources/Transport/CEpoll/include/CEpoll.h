//
//  CEpoll.h
//  CEpoll
//
//  Re-exports the Linux `epoll(7)` readiness API (<sys/epoll.h>) and the `eventfd(2)` wakeup
//  primitive (<sys/eventfd.h>) to Swift: `epoll_create1`, `epoll_ctl`, `epoll_wait`,
//  `struct epoll_event`, the `EPOLL*` flags, and `eventfd` with its `EFD_*` flags (as small inline
//  functions — see below). Swift's platform `Glibc` module surfaces none of these (verified on
//  swift 6.5-dev / Ubuntu noble: neither <sys/epoll.h> nor <sys/eventfd.h> is in Glibc's modulemap),
//  so the epoll transport backbone imports this shim — the same reason SwiftNIO ships its
//  `CNIOLinux` C shim.
//
//  Linux-only: the body is guarded `#if defined(__linux__)`, so the module is inert on Darwin (where the
//  epoll backbone is gated out and this target is not even linked).
//
//  Standards: epoll_create1()/epoll_ctl()/epoll_wait() (epoll(7)); eventfd(2); the descriptors are
//  POSIX.1-2017 sockets carrying TCP (RFC 9293).
//

#ifndef CEPOLL_H
#define CEPOLL_H

#if defined(__linux__)
#include <sys/epoll.h>
#include <sys/eventfd.h>

/// The `EFD_CLOEXEC | EFD_NONBLOCK` flag set for ``CEpoll_eventfd`` — exposed as a function because
/// the `EFD_*` constants are enum-cases-behind-macros the Swift importer does not surface.
static inline int CEpoll_eventfd_wakeup_flags(void) {
    return EFD_CLOEXEC | EFD_NONBLOCK;
}

/// `eventfd(2)` under a shim-stable name (the epoll loop's cross-thread wakeup source).
static inline int CEpoll_eventfd(unsigned int initval, int flags) {
    return eventfd(initval, flags);
}

#include <sys/sendfile.h>

/// Linux `sendfile(2)` under a shim-stable name (<sys/sendfile.h> is likewise absent from Glibc's
/// modulemap): sends up to `count` octets of `in_fd` starting at `offset` to the socket `out_fd`,
/// returning the octets sent, or `-1` with `errno` (`EAGAIN` on a full non-blocking socket buffer) —
/// the G5 zero-copy static-serving primitive.
static inline long CEpoll_sendfile(int out_fd, int in_fd, long offset, unsigned long count) {
    off_t position = (off_t)offset;
    ssize_t sent = sendfile(out_fd, in_fd, &position, (size_t)count);
    return (long)sent;
}
#endif

#endif
