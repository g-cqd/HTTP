//
//  BindContractShutdownTests.swift
//  HTTPTransportTests
//
//  The half of the bind contract a matrix row cannot prove: that `shutdown()` does not RETURN until the
//  listening descriptor is closed. `BindContractTests`' `rebind after stop` row asserts the visible
//  consequence — stop, then bind the same port again, four times — but it is a race, and on a quiet host
//  the loop thread usually wins it. That row passed on macOS against the very code that failed the same
//  row on Linux with `EADDRINUSE` (errno 98 there, 48 on Darwin). A row that only *may* interleave is
//  not a regression test, so the ordering itself is machine-checked here instead.
//
//  Two invariants, both asserted from a point where the interleaving is fixed rather than hoped for:
//
//  1. The event loop's close completion runs strictly AFTER `close(2)`. Asserted from inside the
//     completion, on the loop thread, by rebinding the port right there — one thread, one order, no
//     race in either direction.
//  2. `shutdown()` is still suspended while its close sits unrun. Asserted from a control closure that
//     PARKS the loop thread and only releases once the transport's close is queued behind it — so a
//     `shutdown()` that awaits the close provably cannot have returned, and one that merely enqueues it
//     provably has.
//
//  Standards: `bind(2)`/`listen(2)`/`close(2)`/`getsockname(2)` per POSIX.1-2017 (IEEE Std 1003.1-2017);
//  `EADDRINUSE` is POSIX's answer while a listening socket still holds the local address. TCP RFC 9293
//  over IPv4 RFC 791. CWE-404 (improper resource shutdown or release).
//

import HTTPTestSupport
import Synchronization
import Testing

@testable import HTTPTransport

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

/// The readiness loop that owns a listening descriptor on this platform.
///
/// `POSIXEpoll/` and `POSIXKqueue/` are line-for-line twins here, so one body covers both jobs.
#if canImport(Glibc)
    private typealias ListenerLoop = EpollEventLoop
#else
    private typealias ListenerLoop = KqueueEventLoop
#endif

@Suite("Bind contract — shutdown closes the listener before it returns", .realNetwork)
struct BindContractShutdownTests {
    /// The backbones whose listening descriptor is closed by an event-loop thread, not inline.
    ///
    /// Package.swift builds the kqueue pair only where Darwin is and the epoll one only where Glibc is,
    /// so the two lists are complementary halves of one matrix — see `BindContractBackbone`.
    static let loopBackedBackbones: [TransportBackbone] = {
        #if canImport(Glibc)
            [.posixEpoll]
        #else
            [.posixKqueue, .swiftSystem]
        #endif
    }()

    /// Every POSIX backbone, including the one whose close rides a `DispatchSource` cancel handler.
    static let posixBackbones: [TransportBackbone] = {
        #if canImport(Glibc)
            [.posixEpoll]
        #else
            [.posixKqueue, .swiftSystem, .posixDispatch]
        #endif
    }()

    // MARK: - Invariant 1 — the completion runs after close(2)

    @Test("the loop's close completion runs after close(2): the port rebinds from inside it")
    func closeCompletionRunsAfterTheDescriptorIsClosed() async throws {
        let loop = try ListenerLoop()
        loop.start()
        defer { loop.stop() }
        let listener = try POSIXSocket.makeListenSocket(
            host: "127.0.0.1", port: 0, nonBlocking: true, backlog: 16
        )
        // `-1` distinguishes "the completion never ran" from "it ran and the rebind failed".
        let rebind = Mutex<Int32>(-1)
        await withCheckedContinuation { (closed: CheckedContinuation<Void, Never>) in
            loop.closeDescriptor(listener.descriptor) {
                // On the loop thread, synchronously after `close(2)`: nothing can interleave, so this
                // observation is the ordering itself rather than evidence about it.
                rebind.withLock { $0 = Self.rebindErrno(port: listener.port) }
                closed.resume()
            }
        }
        let outcome = rebind.withLock(\.self)
        #expect(outcome == 0, "the completion ran before close(2): rebind errno \(outcome)")
    }

    // MARK: - Invariant 2 — shutdown() is suspended, not merely fast

    @Test(
        "shutdown() is still suspended while its listener close sits on a parked loop",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)),
        arguments: loopBackedBackbones)
    func shutdownStaysSuspendedUntilTheCloseRuns(_ backbone: TransportBackbone) async throws {
        let transport = try TransportFactory.make(
            TransportConfiguration(
                host: "127.0.0.1", port: 0, backbone: backbone, eventLoopCount: 1
            )
        )
        let stream = try await transport.start()
        let loop = try #require(
            Self.acceptLoop(of: transport),
            "\(backbone) exposes no accept loop to park"
        )
        let hasReturned = Mutex<Bool>(false)
        let observed = Mutex<Bool?>(nil)
        let throwaway = try #require(Self.throwawaySocket(), "socket(2) for the parking fd failed")

        // Park the loop thread inside a control closure of our own — a throwaway descriptor's close —
        // and hold it there until the transport's own close lands in the queue behind it. Control work
        // is FIFO on one thread, so at the moment the spin below exits, the listening descriptor is
        // provably still open and `shutdown()`'s close is provably not yet run.
        loop.closeDescriptor(throwaway) {
            var spins = 0
            while loop.queuedControlWork == 0, spins < Self.spinCeiling {
                spins &+= 1
                if spins > Self.hotSpins {
                    // The hot burst normally converges in a few hundred iterations. If it has not,
                    // this thread is competing for a core with the very task it is waiting for
                    // (`--parallel` runs the whole transport suite alongside), so yield rather than
                    // hold the core to the ceiling.
                    sched_yield()
                }
            }
            // The reading is the assertion: a `shutdown()` that awaits its close cannot have returned,
            // because the only thing that resumes it is queued behind this very closure.
            observed.withLock { $0 = hasReturned.withLock(\.self) }
        }
        await transport.shutdown()
        hasReturned.withLock { $0 = true }
        withExtendedLifetime(stream) {
            // Held so the stream's `onTermination` shutdown does not front-run the explicit one.
        }
        #expect(
            observed.withLock(\.self) == false,
            "\(backbone) returned from shutdown() with its listener close still queued unrun"
        )
    }

    // MARK: - Invariant 3 — a caller that did not perform the close still waits for it

    @Test(
        "a shutdown() that loses the close to another caller still waits for that close",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)),
        arguments: loopBackedBackbones)
    func aJoiningShutdownWaitsForTheCloseItDidNotPerform(_ backbone: TransportBackbone) async throws
    {
        let transport = try TransportFactory.make(
            TransportConfiguration(
                host: "127.0.0.1", port: 0, backbone: backbone, eventLoopCount: 1
            )
        )
        let stream = try await transport.start()
        let port = transport.boundPort
        let loop = try #require(
            Self.acceptLoop(of: transport), "\(backbone) exposes no accept loop")
        let release = Mutex<Bool>(false)
        let joinerSettled = Mutex<Bool>(false)
        let joinerSaw = Mutex<Int32>(-1)
        let throwaway = try #require(Self.throwawaySocket(), "socket(2) for the parking fd failed")

        // Park the loop under the TEST's control this time: the point is to hold the close unrun while
        // a second caller runs the whole of `shutdown()`.
        loop.closeDescriptor(throwaway) {
            var spins = 0
            while !release.withLock(\.self), spins < Self.spinCeiling {
                spins &+= 1
                if spins > Self.hotSpins {
                    sched_yield()
                }
            }
        }
        // The performer: takes the descriptor out of the transport's state and enqueues its close.
        let performer = Task { await transport.shutdown() }
        while loop.queuedControlWork == 0 {
            // On exit the close is queued, and the parked loop provably has not run it.
            await Task.yield()
        }
        // The joiner: finds nothing left to close, and must nevertheless not return before it lands.
        let joiner = Task {
            await transport.shutdown()
            joinerSaw.withLock { $0 = Self.rebindErrno(port: port) }
            joinerSettled.withLock { $0 = true }
        }
        // Release only once a non-waiting joiner would have settled. A joiner that awaits the close
        // cannot settle here by construction, so this loop runs to its bound and then frees the loop.
        for _ in 0 ..< Self.joinerSettleYields where !joinerSettled.withLock(\.self) {
            await Task.yield()
        }
        release.withLock { $0 = true }
        await joiner.value
        await performer.value
        withExtendedLifetime(stream) {
            // Held until the listener is down.
        }
        #expect(
            joinerSaw.withLock(\.self) == 0,
            "\(backbone) let a joining shutdown() return while the port was still held"
        )
    }

    // MARK: - Idempotence

    @Test(
        "shutdown() is idempotent under concurrent and repeated calls, and still frees the port",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)),
        arguments: posixBackbones)
    func shutdownIsIdempotentAndStillReleasesThePort(_ backbone: TransportBackbone) async throws {
        // One configured port across every cycle: if any of the overlapping shutdowns resolved before
        // the close, or double-closed a descriptor another cycle had reused, the next bind fails.
        let port = try BindContractSubject.unusedPort(BindContractSubject.streamSocketType)
        for cycle in 0 ..< 3 {
            let transport = try TransportFactory.make(
                TransportConfiguration(host: "127.0.0.1", port: port, backbone: backbone)
            )
            let stream = try await transport.start()
            #expect(
                transport.boundPort == port,
                "\(backbone) cycle \(cycle) bound \(transport.boundPort), not \(port)"
            )
            // Shutdown-during-shutdown: four overlapping callers, then one strictly afterwards.
            await withTaskGroup(of: Void.self) { group in
                for _ in 0 ..< 4 {
                    group.addTask { await transport.shutdown() }
                }
            }
            await transport.shutdown()
            withExtendedLifetime(stream) {
                // Held until the listener is down.
            }
        }
    }

    // MARK: - Helpers

    /// How long the parking closure spins before giving up, so a regression fails the expectation
    /// rather than wedging the loop thread for the whole suite.
    private static let spinCeiling = 2_000_000

    /// How much of that ceiling is spent hot, before falling back to `sched_yield(2)`.
    private static let hotSpins = 100_000

    /// Scheduling opportunities a joining `shutdown()` gets before the parked loop is released.
    ///
    /// A joiner that does NOT wait for the close has no suspension point between entering `shutdown()`
    /// and returning, so it settles on its first turn; this bound gives it two orders of magnitude more
    /// than that. A joiner that does wait cannot settle here at all, so the bound is simply spent.
    private static let joinerSettleYields = 200

    /// The accept loop of a loop-backed transport, or `nil` for a backbone that has none.
    private static func acceptLoop(of transport: any ServerTransport) -> ListenerLoop? {
        #if canImport(Glibc)
            (transport as? POSIXEpollTransport)?.acceptLoop
        #else
            if let kqueue = transport as? POSIXKqueueTransport {
                kqueue.acceptLoop
            }
            else {
                (transport as? SwiftSystemTransport)?.acceptLoop
            }
        #endif
    }

    /// An unbound TCP socket, used purely as something for the loop thread to close while parked.
    private static func throwawaySocket() -> Int32? {
        let descriptor = socket(AF_INET, BindContractSubject.streamSocketType, 0)
        return descriptor >= 0 ? descriptor : nil
    }

    /// Binds `port` on the IPv4 loopback and reports `0` on success or the `bind(2)` errno.
    ///
    /// Deliberately without `SO_REUSEADDR`: the question is whether the previous listener still holds
    /// the address, and POSIX.1-2017 answers `EADDRINUSE` for exactly as long as it does. A freshly
    /// bound listener that never accepted anything leaves no `TIME_WAIT` behind to confuse that.
    private static func rebindErrno(port: UInt16) -> Int32 {
        let descriptor = socket(AF_INET, BindContractSubject.streamSocketType, 0)
        guard descriptor >= 0 else {
            return errno
        }
        defer { close(descriptor) }
        var address = sockaddr_in()
        #if canImport(Darwin)
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        return bound ? 0 : errno
    }
}
