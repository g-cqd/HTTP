//
//  HTTPServer+Timeout.swift
//  HTTPServer
//
//  The deadline helper shared by the request-read loop and the HTTP/2 serve loop: race an operation
//  against the injected `Clock`, cancelling the loser. The cancellation propagates to the connection's
//  read (which honors it — closing the descriptor to unblock a stalled syscall), so a stalled peer
//  cannot pin a task past its Slowloris / idle deadline (RFC 9112 §9.3 defenses).
//

extension HTTPServer {

    /// A sentinel for an operation that exceeded its deadline.
    struct TimeoutError: Error {}

    /// Runs `operation`, cancelling it and throwing ``TimeoutError`` if it outlasts `duration`.
    func withTimeout<Value: Sendable>(
        _ duration: Duration,
        _ operation: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        let clock = self.clock
        return try await withThrowingTaskGroup(of: Value.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await clock.sleep(for: duration)
                throw TimeoutError()
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else { throw TimeoutError() }
            return result
        }
    }
}
