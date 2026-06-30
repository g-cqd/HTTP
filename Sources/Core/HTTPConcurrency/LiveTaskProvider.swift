//
//  LiveTaskProvider.swift
//  HTTPConcurrency
//
//  The shipped live default the ``TaskProvider`` seam points at: a detached `Task`. Defaulting a library
//  parameter to it changes nothing in production; only a host or test overrides the seam.
//

/// The shipped live ``TaskProvider``: spawns the operation in an unstructured `Task`.
public enum LiveTaskProvider {
    /// Spawns `operation` in a detached `Task` — the production default.
    public static let spawn: TaskProvider = { operation in
        Task { await operation() }
    }
}
