//
//  TaskProvider.swift
//  HTTPConcurrency
//
//  Thin compatibility facade over `AemiRuntime`'s `LiveTaskProvider`. Keeps the closure-style
//  `TaskSpawnProvider` / `LiveTaskProvider.spawn` convenience while avoiding name collisions with
//  `AemiRuntime.TaskProvider` / `AemiRuntime.LiveTaskProvider` (which are re-exported directly via
//  `AemiRuntimeReexports.swift`).
//

public import AemiRuntime

/// The injection point for spawning a fire-and-forget background task running `operation`.
public typealias TaskSpawnProvider =
    @Sendable (_ operation: @escaping @Sendable () async -> Void) -> Void

extension AemiRuntime.LiveTaskProvider {
    /// Spawns `operation` in an unstructured `Task` through `AemiRuntime.LiveTaskProvider`.
    public static let spawn: TaskSpawnProvider = { operation in
        AemiRuntime.LiveTaskProvider().task { await operation() }
    }
}
