//
//  HangingConnection.swift
//  HTTPTestSupport
//
//  A reusable fake whose `receive` blocks until the task is cancelled — for exercising the server's
//  read-timeout and per-client connection-cap paths deterministically, with no `Task.sleep`. The
//  block is an `AsyncGate` that is never opened (so it suspends the Task cooperatively and throws
//  `CancellationError` when cancelled), and an optional probe records the admission decision so a test
//  can `await` it instead of guessing with a sleep.
//

public import HTTPTransport

/// An in-memory ``TransportConnection`` whose `receive` blocks until cancelled.
public actor HangingConnection: TransportConnection {
    /// The connection's stable identifier.
    nonisolated public let id: TransportConnectionID

    /// The peer's address.
    nonisolated public let peer: TransportAddress

    private let gate = AsyncGate()
    private let admissionProbe: AsyncEventProbe<TransportConnectionID>?
    private var decided = false
    private var closed = false

    /// Creates a hanging connection.
    ///
    /// When `admissionProbe` is supplied, the connection records its `id` the first time the server
    /// either reads from it (admitted) or closes it (rejected), so a test can `await
    /// probe.wait(forAtLeast:)` for every admission decision instead of sleeping.
    public init(
        id: TransportConnectionID,
        peer: TransportAddress = TransportAddress(host: "hang", port: 0),
        admissionProbe: AsyncEventProbe<TransportConnectionID>? = nil
    ) {
        self.id = id
        self.peer = peer
        self.admissionProbe = admissionProbe
    }

    /// Records the admission decision (admitted), then blocks until the task is cancelled.
    public func receive(maxLength _: Int) async throws -> [UInt8]? {
        recordDecision()
        try await gate.waitUntilOpen()  // never opened → suspends until cancelled
        return nil
    }

    /// Discards sent bytes.
    public func send(_: [UInt8]) async {
        // no-op: a hanging connection discards all sent bytes.
    }

    /// Marks the connection closed, recording the admission decision (rejected) if not already made.
    public func close() async {
        closed = true
        recordDecision()
    }

    /// Whether the connection has been closed (test inspection).
    public func isClosed() -> Bool { closed }

    private func recordDecision() {
        guard !decided else {
            return
        }
        decided = true
        admissionProbe?.record(id)
    }
}
