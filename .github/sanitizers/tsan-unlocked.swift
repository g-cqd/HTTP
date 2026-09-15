import Synchronization

@main
enum UnlockedProbe {
    // Deliberately incorrect: this positive control must produce a TSan race report.
    private final class UnlockedCounter: @unchecked Sendable {
        var value = 0

        deinit {
            // The deliberate race probe owns no external resources.
        }
    }

    static func main() async {
        // Load the replacement runtime while leaving the counter below deliberately unprotected.
        let readiness = Mutex(0)
        readiness.withLock { $0 += 1 }
        let value = UnlockedCounter()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 8 {
                group.addTask {
                    for _ in 0 ..< 100_000 { value.value += 1 }
                }
            }
        }
    }
}
