//
//  RawConnectionFixture.swift
//  HTTPTransportTests
//
//  The socket pair, reactor and raw connection every direction-ownership suite is built on, extracted
//  from `ConnectionDirectionOwnershipTests` so the cancellation matrix can share it rather than
//  duplicate it. One file per type; nothing else changed in the move.
//
//  PORTABLE ON PURPOSE. The reactor and the connection are picked by `#if`, so every suite that uses
//  this fixture runs unchanged against the kqueue backbone on Darwin and the epoll mirror on Linux.
//  The ownership defect is not a kqueue defect, and a fixture that only ran on one of them is how the
//  epoll half went three unbuilt changes deep in the first place.
//
//  Standards: socketpair()/read()/write()/shutdown()/close() per POSIX.1-2017 (IEEE Std 1003.1-2017);
//  TCP framing per RFC 9293. Readiness via BSD kqueue (Darwin) or epoll(7) (Linux).
//

#if canImport(Darwin) || canImport(Glibc)

    internal import Dispatch
    internal import Synchronization

    #if canImport(Darwin)
        import Darwin

        /// The Darwin reactor and the connection it drives.
        typealias ReactorLoop = KqueueEventLoop
        typealias ReactorConnection = POSIXKqueueConnection
    #elseif canImport(Glibc)
        import Glibc

        /// The Linux mirror of the reactor and the connection it drives.
        typealias ReactorLoop = EpollEventLoop
        typealias ReactorConnection = POSIXEpollConnection
    #endif

    import HTTPTestSupport
    import Testing

    @testable import HTTPTransport

    /// A socket pair, a kqueue loop and a connection over the server end — what every test builds on.
    ///
    /// Deliberately a class: it owns descriptors and a running loop thread, and `deinit` is the only
    /// place that can release them once a test body has thrown partway.
    final class RawConnectionFixture: Sendable {
        /// Comfortably larger than any `window` below, so a send blocks partway and re-arms.
        static let payload = [UInt8](repeating: 0x41, count: 128 * 1_024)

        /// The recorded marker for a receive that ended at end of stream rather than taking an octet.
        static let endOfStream = -1

        let loop: ReactorLoop
        let connection: ReactorConnection
        let client: Int32
        private let ownsLoop: Bool
        private let clientClosed = Atomic<Bool>(false)

        /// Builds the pair and the connection; `window` shrinks both socket buffers so a modest
        /// payload blocks partway, and `loop` reuses an already-running loop.
        init(window: Int32? = nil, loop: ReactorLoop? = nil) throws {
            let running = try loop ?? ReactorLoop()
            self.ownsLoop = loop == nil
            if loop == nil {
                running.start()
            }
            self.loop = running
            let pair = try Self.makeSocketPair(window: window)
            self.client = pair.client
            self.connection = ReactorConnection(
                id: TransportConnectionID(1),
                descriptor: pair.server,
                peer: TransportAddress(host: "local", port: 0),
                eventLoop: running
            )
        }

        deinit {
            connection.cancel()
            if !clientClosed.exchange(true, ordering: .acquiringAndReleasing) {
                close(client)
            }
            if ownsLoop {
                loop.stop()
            }
        }

        /// Cancels every task in `tasks` — the teardown every test runs on its way out.
        static func cancel(_ tasks: [Task<Void, Never>]) {
            for task in tasks {
                task.cancel()
            }
        }

        /// Closes the peer end early — the departed-peer / `EPIPE` setup.
        func closeClient() {
            if !clientClosed.exchange(true, ordering: .acquiringAndReleasing) {
                close(client)
            }
        }

        /// Lets every spawned task reach its park, or its place in the queue behind the owner.
        ///
        /// There is no public "the operation is parked" hook on a `TransportConnection`, so this
        /// sequences SETUP only, exactly as the existing cancellation conformance probe does. Every
        /// oracle is event-driven: no octet is written and no close happens until this returns, so
        /// the operations demonstrably overlap, and a dropped continuation can only lower a count
        /// that is then waited for against its own timeout.
        func settle() async throws {
            try await Task.sleep(for: .milliseconds(150))
        }

        /// Spawns `count` receives, recording the octet each took (or ``endOfStream`` at EOF).
        func spawnReceives(
            _ count: Int,
            into probe: AsyncEventProbe<Int>
        ) -> [Task<Void, Never>] {
            (0 ..< count)
                .map { _ in
                    Task {
                        let eof = Self.endOfStream
                        guard let chunk = try? await self.connection.receive(maxLength: 1)
                        else {
                            probe.record(eof)
                            return
                        }
                        probe.record(chunk.first.map(Int.init) ?? eof)
                    }
                }
        }

        /// Spawns `count` sends of ``payload``, recording each sender's index as it settles.
        func spawnSends(_ count: Int, into probe: AsyncEventProbe<Int>) -> [Task<Void, Never>] {
            (0 ..< count)
                .map { index in
                    Task {
                        try? await self.connection.send(Self.payload)
                        probe.record(index)
                    }
                }
        }

        /// Drains the peer end off the cooperative pool until `total` octets have arrived.
        func drainPeer(untilAtLeast total: Int) -> AsyncEventProbe<Int> {
            let drained = AsyncEventProbe<Int>()
            let peer = client
            DispatchQueue.global(qos: .userInitiated)
                .async {
                    var seen = 0
                    var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
                    while seen < total {
                        let count = read(peer, &buffer, buffer.count)
                        guard count > 0 else { break }
                        seen += count
                    }
                    drained.record(seen)
                }
            return drained
        }

        private static func makeSocketPair(
            window: Int32?
        ) throws -> (server: Int32, client: Int32) {
            var descriptors = [Int32](repeating: 0, count: 2)
            // Glibc vends SOCK_STREAM as the C enum `__socket_type`; `socketpair` takes Int32.
            #if canImport(Darwin)
                let stream = SOCK_STREAM
            #else
                let stream = Int32(SOCK_STREAM.rawValue)
            #endif
            let made = descriptors.withUnsafeMutableBufferPointer { buffer in
                socketpair(AF_UNIX, stream, 0, buffer.baseAddress)
            }
            try #require(made == 0, "socketpair(2) failed with errno \(errno)")
            POSIXSocket.setNonBlocking(descriptors[0])
            POSIXSocket.setNoSIGPIPE(descriptors[0])
            POSIXSocket.setNoSIGPIPE(descriptors[1])
            if var window {
                let width = socklen_t(MemoryLayout<Int32>.size)
                _ = setsockopt(descriptors[0], SOL_SOCKET, SO_SNDBUF, &window, width)
                _ = setsockopt(descriptors[1], SOL_SOCKET, SO_RCVBUF, &window, width)
            }
            return (descriptors[0], descriptors[1])
        }
    }

#endif
