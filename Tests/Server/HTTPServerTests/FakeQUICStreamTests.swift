import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@Suite("Fake QUIC stream cancellation")
struct FakeQUICStreamTests {
    @Test
    func `cancellation releases a parked receive`() async throws {
        let sut = FakeQUICStream(id: QUICStreamID(2), direction: .unidirectional)
        let completed = AsyncEventProbe<Bool>()
        let receiving = Task {
            await #expect(throws: CancellationError.self) {
                try await sut.receive()
            }
            completed.record(true)
        }
        do {
            try await settle { sut.hasPendingReceive }
            receiving.cancel()
            _ = try await completed.wait(forAtLeast: 1)
        }
        catch {
            sut.finishInbound()
            await receiving.value
            throw error
        }
        await receiving.value
        #expect(!sut.hasPendingReceive)
    }
}
