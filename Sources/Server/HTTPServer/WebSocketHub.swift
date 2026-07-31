//
//  WebSocketHub.swift
//  HTTPServer
//
//  A topic-based publish/subscribe hub for WebSocket connections (RFC 6455): a connection subscribes to
//  topics, and a published ``WebSocketMessage`` is fanned out to every subscriber's sink — the
//  per-connection send channel the server drives. The server registers a sink when a hub-backed
//  WebSocket upgrades and removes it on disconnect; a handler publishes via the hub it captured.
//
//  This used to be one `actor` holding `[String: Set<UInt64>]` (2026-07-31 audit, finding 16). Two of
//  that shape's defects are addressed here:
//
//    • Every topic, subscription, publication and removal serialized on ONE executor, so a hub was a
//      global chokepoint no matter how many unrelated topics it carried. It is now partitioned across
//      independently locked shards.
//    • `remove` scanned `Array(topics.keys)` — O(all topics), plus one array allocation of every topic
//      name — on every disconnect. Measured on this codebase before the change: 0.86 ms at 1 000
//      topics, 7.5 ms at 10 000, 70 ms at 100 000, per disconnect, i.e. exactly linear. A disconnect
//      storm against a hub with a large topic space was therefore a CPU-exhaustion amplifier (CWE-407,
//      algorithmic complexity). A reverse token → topics index makes removal proportional to the
//      connection's own subscriptions instead.
//

internal import HTTPConcurrency
internal import Synchronization
public import WebSocket

/// A topic fan-out hub for WebSocket connections — subscribe a connection's sink, publish to a topic.
///
/// ## Lock order
///
/// Two independent ``ShardedMutex`` partitions back the hub: a *subscriber* partition keyed by token,
/// and a *topic* partition keyed by topic name. Where both are needed the subscriber shard is taken
/// first and the topic shard second, **never the reverse**. That single rule is what makes the design
/// deadlock-free, and every entry point below obeys it:
///
/// | Operation | Locks taken |
/// | --- | --- |
/// | ``register(_:)`` | subscriber |
/// | ``subscribe(_:to:)`` | subscriber, then topic (nested) |
/// | ``unsubscribe(_:from:)`` | subscriber, then topic (nested) |
/// | ``remove(_:)`` | subscriber, released, then each held topic in turn |
/// | ``publish(_:to:)`` | topic only |
public final class WebSocketHub: Sendable {
    /// A per-connection delivery channel: a closure that sends one ``WebSocketMessage`` to a connection.
    public typealias Sink = @Sendable (WebSocketMessage) -> Void

    /// One registered connection: its sink, plus the reverse index of the topics it holds.
    ///
    /// The reverse index is the whole point of this shape: ``remove(_:)`` reads this set instead of
    /// scanning every topic, so a disconnect costs O(that connection's subscriptions).
    private struct Subscriber: Sendable {
        let sink: Sink
        var topics: Set<String> = []
    }

    private let nextToken = Atomic<UInt64>(0)
    private let subscribers: ShardedMutex<[UInt64: Subscriber]>
    private let topics: ShardedMutex<[String: [UInt64: Sink]]>
    /// Topic-map entries examined by ``remove(_:)`` since creation — the proportionality witness.
    ///
    /// Internal, and touched only on the disconnect path (once per topic the connection actually held),
    /// so it costs nothing measurable. It exists because "removal is proportional to the connection's
    /// own subscriptions" is otherwise unobservable from outside, and an unobservable cost property
    /// silently regresses.
    private let removalProbes = Atomic<Int>(0)

    deinit {
        // No teardown beyond ARC; the sharded partitions release with the instance.
    }

    /// Creates an empty hub partitioned across roughly `shards` locks.
    ///
    /// `shards` is a hint, rounded to a power of two by ``ShardedMutex``. Pass `1` when a test needs
    /// every key on one lock.
    public init(shards: Int = 16) {
        subscribers = ShardedMutex(shards: shards) { _ in [:] }
        topics = ShardedMutex(shards: shards) { _ in [:] }
    }

    /// Registers a connection's `sink`, returning a token used to subscribe / unsubscribe / remove it.
    public func register(_ sink: @escaping Sink) -> UInt64 {
        let token = nextToken.wrappingAdd(1, ordering: .relaxed).newValue
        subscribers.withLock(forKey: token) { $0[token] = Subscriber(sink: sink) }
        return token
    }

    /// Subscribes `token` to `topic`, so a message published there reaches that connection.
    ///
    /// The subscriber shard is held across the topic-shard acquisition (the documented order), so the
    /// reverse index and the topic table are updated as one atomic step and can never disagree.
    public func subscribe(_ token: UInt64, to topic: String) {
        subscribers.withLock(forKey: token) { shard in
            guard var subscriber = shard[token] else {
                return  // never registered, or already removed
            }
            let sink = subscriber.sink
            topics.withLock(forKey: topic) { $0[topic, default: [:]][token] = sink }
            subscriber.topics.insert(topic)
            shard[token] = subscriber
        }
    }

    /// Unsubscribes `token` from `topic`.
    public func unsubscribe(_ token: UInt64, from topic: String) {
        subscribers.withLock(forKey: token) { shard in
            guard shard[token]?.topics.remove(topic) != nil else {
                return  // not subscribed; nothing to undo in either index
            }
            detach(token, from: topic)
        }
    }

    /// Removes `token` entirely on disconnect: drops its sink and every subscription it held.
    ///
    /// O(this connection's subscriptions), read straight from the reverse index — not O(all topics).
    /// The subscriber shard is released *before* the topic shards are taken, so a disconnect holding
    /// many subscriptions never pins one subscriber lock across many topic-lock acquisitions. That is
    /// safe under the documented order precisely because the two are never held together here.
    public func remove(_ token: UInt64) {
        let held = subscribers.withLock(forKey: token) { shard in
            shard.removeValue(forKey: token)?.topics ?? []
        }
        removalProbes.wrappingAdd(held.count, ordering: .relaxed)
        for topic in held {
            detach(token, from: topic)
        }
    }

    /// Publishes `message` to every connection subscribed to `topic` (RFC 6455 §5.6 fan-out).
    public func publish(_ message: WebSocketMessage, to topic: String) {
        topics.withLock(forKey: topic) { table in
            guard let members = table[topic] else {
                return
            }
            for sink in members.values {
                sink(message)
            }
        }
    }

    /// The number of connections currently subscribed to `topic` (for metrics and tests).
    public func subscriberCount(of topic: String) -> Int {
        topics.withLock(forKey: topic) { $0[topic]?.count ?? 0 }
    }

    /// Distinct topics currently held, across every shard — a metrics read, not a consistent snapshot.
    public var topicCount: Int {
        topics.withEveryLock(\.count).reduce(0, +)
    }

    /// Topic-map entries examined by removals so far — see ``removalProbes``.
    var removalProbeCount: Int {
        removalProbes.load(ordering: .relaxed)
    }

    /// Drops `token` from the membership of `topic`, retiring that topic once it empties.
    ///
    /// Takes the topic shard only. Called either while the subscriber shard is held
    /// (``unsubscribe(_:from:)``) or with no other lock held (``remove(_:)``) — never while a topic
    /// shard is already held.
    private func detach(_ token: UInt64, from topic: String) {
        topics.withLock(forKey: topic) { table in
            table[topic]?.removeValue(forKey: token)
            if table[topic]?.isEmpty == true {
                table[topic] = nil  // retire the topic so an empty name is not retained forever
            }
        }
    }
}
