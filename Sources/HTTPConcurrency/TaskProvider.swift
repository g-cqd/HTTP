//
//  TaskProvider.swift
//  HTTPConcurrency
//
//  A seam mirroring `Task.init` so async-heavy library code (the transports' shutdown spawns, future
//  background timers) can create tasks through an injected provider instead of an untracked `Task { }`.
//  Shipping default is `LiveTaskProvider` (a transparent forward); tests inject a tracking spy and
//  settle the real handles deterministically. Zero dependencies, no I/O — reuse-safe.
//

/// The role a spawned task plays, which governs whether a tracking spy must settle it.
///
/// `.work` is application work a spy waits for transitively; `.observation` is a long-lived stream /
/// accept loop that never completes on its own, so a spy excludes it from its settle (awaiting it
/// would hang the suite). Library seams default new tasks to `.work` and tag only the genuinely
/// unbounded loops `.observation`.
public enum TaskRole: Sendable, Hashable {
    case work
    case observation
}

/// A seam mirroring `Task.init` so async-heavy code can spawn tasks through an injected provider.
///
/// The shipped default is ``LiveTaskProvider`` (a transparent forward to `Task.init`); tests inject a
/// tracking provider and `await` its settle to drain the real handles deterministically rather than
/// racing on a `Task.sleep`.
///
/// The requirement carries `sending` + `@isolated(any)` so an isolated operation crosses into the
/// task exactly as `Task.init` allows; `@_inheritActorContext` keeps a `provider.task { }` call site
/// inheriting the caller's actor where the closure is formed directly (the convenience forms below).
public protocol TaskProvider: Sendable {
    @discardableResult
    func task<Success: Sendable>(
        role: TaskRole,
        priority: TaskPriority?,
        @_inheritActorContext operation: sending @escaping @isolated(any) () async -> Success
    ) -> Task<Success, Never>

    @discardableResult
    func task<Success: Sendable>(
        role: TaskRole,
        priority: TaskPriority?,
        @_inheritActorContext operation: sending @escaping @isolated(any) () async throws -> Success
    ) -> Task<Success, any Error>
}

extension TaskProvider {
    /// Ergonomic convenience: defaults `role`/`priority` and takes a trailing closure.
    ///
    /// The unlabeled `_ operation` selector differs from the labeled `operation:` requirement, so this
    /// forward resolves to the requirement (never to itself) — recursion-free.
    @discardableResult
    public func task<Success: Sendable>(
        role: TaskRole = .work,
        priority: TaskPriority? = nil,
        @_inheritActorContext _ operation: sending @escaping @isolated(any) () async -> Success
    ) -> Task<Success, Never> {
        task(role: role, priority: priority, operation: operation)
    }

    /// Throwing form of the ergonomic convenience.
    @discardableResult
    public func task<Success: Sendable>(
        role: TaskRole = .work,
        priority: TaskPriority? = nil,
        @_inheritActorContext _ operation:
            sending @escaping @isolated(any) () async throws -> Success
    ) -> Task<Success, any Error> {
        task(role: role, priority: priority, operation: operation)
    }
}

/// The shipped default: a transparent forward to `Task.init`, so code that takes a ``TaskProvider``
/// defaulting to `LiveTaskProvider()` behaves byte-for-byte like a raw `Task { }` in production.
///
/// `role` is irrelevant live (only a tracking spy reads it) and is accepted-and-ignored.
public struct LiveTaskProvider: TaskProvider {
    /// Creates the live provider.
    public init() {}

    /// Spawns a non-throwing task — a transparent forward to `Task.init` (`role` is ignored).
    @discardableResult
    public func task<Success: Sendable>(
        role: TaskRole,
        priority: TaskPriority?,
        @_inheritActorContext operation: sending @escaping @isolated(any) () async -> Success
    ) -> Task<Success, Never> {
        Task(priority: priority, operation: operation)
    }

    /// Spawns a throwing task — a transparent forward to `Task.init` (`role` is ignored).
    @discardableResult
    public func task<Success: Sendable>(
        role: TaskRole,
        priority: TaskPriority?,
        @_inheritActorContext operation: sending @escaping @isolated(any) () async throws -> Success
    ) -> Task<Success, any Error> {
        Task(priority: priority, operation: operation)
    }
}
