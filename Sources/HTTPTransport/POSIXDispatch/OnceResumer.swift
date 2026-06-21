//
//  OnceResumer.swift
//  HTTPTransport
//
//  Resumes a CheckedContinuation at most once. DispatchIO read/write handlers may be invoked more
//  than once per operation, so this guards against the double-resume crash. State is held in a
//  Synchronization `Mutex`, making the type genuinely `Sendable` (no `@unchecked`).
//

internal import Synchronization

/// Resumes a `CheckedContinuation` at most once, regardless of how many times its callback fires.
final class OnceResumer<Success: Sendable>: Sendable {

    private let continuation: Mutex<CheckedContinuation<Success, any Error>?>

    init(_ continuation: CheckedContinuation<Success, any Error>) {
        self.continuation = Mutex(continuation)
    }

    func resume(returning value: Success) {
        take()?.resume(returning: value)
    }

    func resume(throwing error: any Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<Success, any Error>? {
        continuation.withLock { pending in
            defer { pending = nil }
            return pending
        }
    }
}
