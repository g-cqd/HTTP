//
//  ReadinessProbe.swift
//  HTTPObservability
//
//  The drain signal behind `/readyz`: a shared, lock-free flag the app flips at the start of its
//  graceful-shutdown path (alongside `HTTPServer.shutdown()`), so a load balancer's readiness check
//  starts failing and stops routing new requests while in-flight ones finish. A reference type so the
//  one instance is shared by the route and the shutdown handler; no coupling to the server internals.
//

internal import Synchronization

/// A shared readiness flag — ready until the app calls ``beginDraining()`` for a graceful shutdown.
public final class ReadinessProbe: Sendable {
    private let draining = Atomic<Bool>(false)

    /// Creates a probe in the ready state.
    public init() {
        // Starts ready; the app calls beginDraining() to flip it during graceful shutdown.
    }

    deinit {
        // No teardown beyond ARC; the Atomic releases with the instance.
    }

    /// Whether the server is still ready to accept new work (false once draining).
    public var isReady: Bool {
        !draining.load(ordering: .acquiring)
    }

    /// Marks the server as draining (idempotent); `/readyz` then reports 503.
    public func beginDraining() {
        draining.store(true, ordering: .releasing)
    }
}
