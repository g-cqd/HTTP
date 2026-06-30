//
//  TaskProvider.swift
//  HTTPConcurrency
//
//  The injection point for "spawn an unstructured background task", parallel to ``MonotonicNowProvider``
//  (`NowProvider.swift`). A library takes `spawn: TaskProvider = LiveTaskProvider.spawn`, and a host or a
//  test substitutes a provider — to pin a priority or executor, count spawned tasks, or run them inline —
//  without hard-coding `Task {}`. The shipped ``LiveTaskProvider`` is exactly `Task { await operation() }`,
//  so defaulting to it changes nothing in production; only a host or test overrides it.
//

/// The injection point for spawning a fire-and-forget background task running `operation`.
public typealias TaskProvider =
    @Sendable (_ operation: @escaping @Sendable () async -> Void) -> Void
