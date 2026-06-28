//
//  CEpoll.h
//  CEpoll
//
//  Re-exports the Linux `epoll(7)` readiness API (<sys/epoll.h>) to Swift: `epoll_create1`,
//  `epoll_ctl`, `epoll_wait`, `struct epoll_event`, and the `EPOLL*` flags. Swift's platform `Glibc`
//  module does not surface any of these (verified on swift 6.5-dev / Ubuntu noble), so the epoll
//  transport backbone imports this shim — the same reason SwiftNIO ships its `CNIOLinux` C shim.
//
//  Linux-only: the body is guarded `#if defined(__linux__)`, so the module is inert on Darwin (where the
//  epoll backbone is gated out and this target is not even linked).
//
//  Standards: epoll_create1()/epoll_ctl()/epoll_wait() (epoll(7)); the descriptors are POSIX.1-2017
//  sockets carrying TCP (RFC 9293).
//

#ifndef CEPOLL_H
#define CEPOLL_H

#if defined(__linux__)
#include <sys/epoll.h>
#endif

#endif
