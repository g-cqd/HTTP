import HTTPTestSupport
import HTTPTransport
import Testing

@Suite
struct ControllableConnectionTests {
    @Test
    func `cancelling a parked receive releases the waiter`() async throws {
        let sut = ControllableConnection()
        let completed = AsyncEventProbe<Void>()
        let receiving = Task {
            defer { completed.record(()) }
            return try await (sut as any TransportConnection).receive(maxLength: 2)
        }
        do {
            try await sut.waitForReceive()
            receiving.cancel()
            _ = try await completed.wait(forAtLeast: 1, timeout: .seconds(1))
        }
        catch {
            await sut.close()
            _ = try? await receiving.value
            throw error
        }
        await #expect(throws: CancellationError.self) { _ = try await receiving.value }
    }
}
