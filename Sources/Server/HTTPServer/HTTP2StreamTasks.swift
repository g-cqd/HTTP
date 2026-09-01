//
//  HTTP2StreamTasks.swift
//  HTTPServer
//
//  The dispatched work one HTTP/2 connection is carrying, one entry per stream: what the EOF drain
//  waits on, what a peer RST_STREAM (RFC 9113 §6.4) cancels, and what connection teardown awaits.
//
//  Ending a stream's *inbound* is not enough to end its handler. Abandoning the body channel unblocks a
//  handler parked reading the body, but one parked anywhere else — a database call, a sleep, a lock, a
//  buffered request that has no body channel at all — keeps running until the whole connection dies. On
//  a reset that is work the server is doing for a request the client has explicitly withdrawn, which is
//  precisely the amplification Rapid Reset exploits (CVE-2023-44487).
//
//  Audit finding 6 gave streaming requests and RFC 8441 tunnels a cancel handle by nesting an
//  unstructured `Task` INSIDE a task-group child, and deferred buffered requests because that shape
//  "would pay an extra `Task` plus a `Mutex` per request against a 200k-rps target". Measured, that was
//  right about the shape and wrong about the conclusion: the nested shape costs +5 mallocs and +20 %
//  instructions per buffered request, but the nesting is what costs it. Dispatching the unstructured
//  task INSTEAD of the group child — registered here, so there is still exactly one task per request —
//  measures identical to no cancellation at all. See `http2/dispatch/buffered-*` and the R5-P0d commit.
//
//  The trade is that the group no longer owns these tasks, so this type owns them instead:
//  ``shutdown()`` cancels and awaits every outstanding one, called from the same function that owns the
//  group. The lifetime is still lexically bounded by the serve loop — by an explicit `await` rather
//  than by the group's implicit one — and a task can now be cancelled individually, which a group child
//  never could.
//
//  It also subsumes the two counters that tracked the same thing less precisely: `dispatched: Set` for
//  requests and `pendingTunnels: Int` for tunnels. One table, one `isEmpty`, and "the accounting came
//  back to zero" is a single assertion — which is what a counter silently drifting on the reset path
//  cost in the first place.
//
//  Bounded by `maxConcurrentStreams`: an entry is created when work is dispatched and dropped when that
//  work reports back, and every dispatch path reports back unconditionally — `.requestReady` even for a
//  cancelled handler, `.tunnelEnded` even for a cancelled pump. A table keyed by a peer-chosen stream
//  id that any exit path forgot to clear would grow without bound (CWE-770).
//

internal import HTTP2
internal import Synchronization

/// The per-stream dispatched work of one HTTP/2 connection: the drain gate and the cancel handles.
final class HTTP2StreamTasks: Sendable {
    private let tasks = Mutex<[HTTP2StreamID: Task<Void, Never>]>([:])

    deinit {
        // No teardown beyond ARC: `shutdown()` is what ends the tasks, and the serve loop calls it
        // before this table can go out of scope.
    }

    /// Whether this connection is carrying no dispatched work at all — the EOF drain's gate.
    var isEmpty: Bool { tasks.withLock(\.isEmpty) }

    /// The number of streams with dispatched work outstanding (test inspection).
    var count: Int { tasks.withLock(\.count) }

    /// Records the task dispatched for one stream.
    ///
    /// Called on the consumer, in the same straight line as the `Task` it registers, so there is no
    /// window in which a stream has work in flight that this table does not know about — the race the
    /// nested shape needed a three-state handshake to close.
    func register(_ task: Task<Void, Never>, for streamID: HTTP2StreamID) {
        tasks.withLock { $0[streamID] = task }
    }

    /// Cancels one stream's dispatched work, if any (RFC 9113 §6.4).
    ///
    /// The entry stays: cancellation is a request, not a completion, and the drain must keep waiting
    /// until the work actually reports back. Idempotent, and a no-op for a stream that dispatched
    /// nothing — a stream can be reset by the peer and swept as stalled, and both funnel through the
    /// same teardown.
    func cancel(_ streamID: HTTP2StreamID) {
        tasks.withLock { $0[streamID] }?.cancel()
    }

    /// Drops one stream, whose work has reported back and owes the connection nothing more.
    func release(_ streamID: HTTP2StreamID) {
        tasks.withLock { $0[streamID] = nil }
    }

    /// Cancels every outstanding task and waits for all of them — connection teardown's join.
    ///
    /// This is what replaces the task group's implicit join, so `serveHTTP2` still returns only once no
    /// handler or pump is running: an admission slot is released when it returns (audit F8), and work
    /// outliving its own connection's slot is exactly what that ceiling exists to prevent. Cancel every
    /// task before awaiting any, so they unwind concurrently rather than one at a time.
    func shutdown() async {
        let outstanding = tasks.withLock { tasks -> [Task<Void, Never>] in
            defer { tasks.removeAll() }
            return Array(tasks.values)
        }
        for task in outstanding {
            task.cancel()
        }
        for task in outstanding {
            await task.value
        }
    }
}
