import Synchronization

@main
enum LockedProbe {
    static func main() async {
        let value = Mutex(0)
        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 8 {
                group.addTask {
                    for _ in 0 ..< 100_000 { value.withLock { $0 += 1 } }
                }
            }
        }
        precondition(value.withLock { $0 == 800_000 })
    }
}
