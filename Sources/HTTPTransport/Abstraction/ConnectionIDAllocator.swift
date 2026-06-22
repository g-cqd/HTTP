//
//  ConnectionIDAllocator.swift
//  HTTPTransport
//
//  A thread-safe source of unique connection identifiers, shared by every backbone so the
//  "monotonic id, relaxed ordering" choice lives in exactly one place instead of being copy-pasted
//  into each transport.
//

internal import Synchronization

/// A thread-safe allocator of monotonically increasing ``TransportConnectionID`` values.
///
/// Every backbone stamps each accepted connection with a unique id (for logging and per-client
/// limits). The ids only need to be *distinct* — not gap-free or globally ordered, and an id implies
/// no cross-thread happens-before — so the counter uses relaxed atomics.
struct ConnectionIDAllocator: ~Copyable, Sendable {

    private let counter = Atomic<UInt64>(0)

    /// Creates an allocator whose first ``next()`` returns id `1`.
    init() {}

    /// Returns the next unique connection id.
    func next() -> TransportConnectionID {
        TransportConnectionID(counter.wrappingAdd(1, ordering: .relaxed).newValue)
    }
}
