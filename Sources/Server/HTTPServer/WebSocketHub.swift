//
//  WebSocketHub.swift
//  HTTPServer
//
//  A topic-based publish/subscribe hub for WebSocket connections (RFC 6455): a connection subscribes to
//  topics, and a published ``WebSocketMessage`` is fanned out to every subscriber's sink — the
//  per-connection send channel the server drives. The server registers a sink when a hub-backed
//  WebSocket upgrades and removes it on disconnect; a handler publishes via the hub it captured.
//
//  This used to be one `actor` holding `[String: Set<UInt64>]` (2026-07-31 audit, finding 16). Three of
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
//    • `publish` invoked every sink while holding actor isolation, so publication latency serialized
//      against every concurrent register/subscribe/remove — and one connection with a wedged send
//      channel froze fan-out on every unrelated topic in the process. Sinks are now snapshotted under
//      the lock and invoked outside it; what that costs in atomicity is documented on the type rather
//      than papered over.
//    • Topic and subscription cardinality were unbounded and attacker-chosen (CWE-770). ``Limits``
//      bounds all four dimensions, and every refusal is reported through the return value.
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
/// | ``publish(_:to:)`` | topic only, and only to snapshot — never across delivery |
///
/// ## Delivery is not atomic with membership
///
/// ``publish(_:to:)`` snapshots the topic's sinks under the topic shard's lock and then invokes them
/// *outside* it. That is deliberate: a sink is application-supplied — it may block on a full send
/// channel, or re-enter the hub — and running it under the lock lets one wedged connection serialize
/// every unrelated topic, which is the defect this type was rewritten to remove.
///
/// The consequence is stated rather than hidden: **a sink registered, subscribed, unsubscribed or
/// removed concurrently with an in-flight publish may or may not receive that message.** Both
/// properties cannot be held at once after delivery leaves the lock, and claiming an atomicity the
/// type does not have would be worse than documenting the race. In particular a removed connection's
/// sink can still be invoked once, from a snapshot taken just before the removal; a sink must
/// therefore tolerate being called after ``remove(_:)`` (the server's does — it deposits into a
/// per-connection mailbox nobody is reading any more). A subscriber that must not miss a message
/// needs an acknowledged, replayable channel, not a fan-out hub.
///
/// ## Bounded cardinality
///
/// On any endpoint that lets a client name its own room, the topic name, the topic count and the
/// subscription count are all attacker-chosen. ``Limits`` bounds them, and every refusal is *reported*
/// rather than swallowed — ``register(_:)`` answers `nil`, ``subscribe(_:to:)`` answers
/// ``Subscription/refused(_:)`` with the specific ``Refusal``. A silent refusal would leave the caller
/// believing a connection is subscribed to a topic it will never hear from. The server turns either
/// into a `1013` Close (RFC 6455 §7.4.1).
///
/// Refusal, never eviction: an admission table must not let an attacker-chosen newcomer displace a
/// tracked legitimate connection, because that hands the attacker a way to knock any victim off the
/// hub on demand — the same trade ``BoundedLRU/Overflow/reject`` exists for.
public final class WebSocketHub: Sendable {
    /// A per-connection delivery channel: a closure that sends one ``WebSocketMessage`` to a connection.
    public typealias Sink = @Sendable (WebSocketMessage) -> Void

    /// Cardinality bounds on the attacker-reachable dimensions of a hub (CWE-770).
    public struct Limits: Sendable {
        /// Connections the hub holds sinks for at once.
        public var maxSubscribers: Int

        /// Distinct topic names the hub holds at once.
        public var maxTopics: Int

        /// Topics one connection may hold subscriptions to.
        public var maxSubscriptionsPerConnection: Int

        /// The longest topic name, in UTF-8 octets, the hub accepts.
        public var maxTopicNameLength: Int

        /// Creates a set of bounds; the defaults suit a public endpoint.
        public init(
            maxSubscribers: Int = 65_536,
            maxTopics: Int = 65_536,
            maxSubscriptionsPerConnection: Int = 64,
            maxTopicNameLength: Int = 256
        ) {
            self.maxSubscribers = maxSubscribers
            self.maxTopics = maxTopics
            self.maxSubscriptionsPerConnection = maxSubscriptionsPerConnection
            self.maxTopicNameLength = maxTopicNameLength
        }

        /// The default bounds.
        public static let `default` = Self()
    }

    /// Why the hub refused a subscription.
    ///
    /// Distinct cases because the caller's correct response differs: a stale token is that
    /// connection's problem, while an exhausted budget is the server's and is worth retrying later.
    public enum Refusal: Sendable, Equatable {
        /// The token is not registered — never issued, or the connection has already been removed.
        case unknownToken

        /// The topic name was empty.
        case emptyTopicName

        /// The topic name exceeded ``Limits/maxTopicNameLength`` UTF-8 octets.
        case topicNameTooLong

        /// The topic name held an octet outside VCHAR (`%x21-7E`, RFC 5234 §B.1).
        ///
        /// Control octets in an attacker-chosen name reach logs and metric dimensions verbatim
        /// (CWE-117, log injection), and a name is retained per topic and compared on every publish.
        case topicNameNotVisibleASCII

        /// This connection already holds ``Limits/maxSubscriptionsPerConnection`` topics.
        case connectionSubscriptionLimit

        /// The hub already holds ``Limits/maxTopics`` distinct topics.
        case topicLimit
    }

    /// What ``subscribe(_:to:)`` did.
    public enum Subscription: Sendable, Equatable {
        /// The connection is subscribed to the topic (it may already have been — this is idempotent).
        case admitted

        /// Nothing was subscribed, for this reason.
        case refused(Refusal)

        /// Whether the connection is subscribed — the check a caller makes before proceeding.
        public var isAdmitted: Bool {
            self == .admitted
        }
    }

    /// One registered connection: its sink, plus the reverse index of the topics it holds.
    ///
    /// The reverse index is the whole point of this shape: ``remove(_:)`` reads this set instead of
    /// scanning every topic, so a disconnect costs O(that connection's subscriptions).
    private struct Subscriber: Sendable {
        let sink: Sink
        var topics: Set<String> = []
    }

    private let limits: Limits
    private let nextToken = Atomic<UInt64>(0)
    private let subscribers: ShardedMutex<[UInt64: Subscriber]>
    private let topics: ShardedMutex<[String: [UInt64: Sink]]>
    private let maxSubscribersPerShard: Int
    private let maxTopicsPerShard: Int
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

    /// Creates an empty hub bounded by `limits` and partitioned across roughly `shards` locks.
    ///
    /// `shards` is a hint. As in ``SharedBoundedLRU``, it is clamped to the budget being divided and
    /// rounded *down* to a power of two, so `shardCount × perShardBudget ≤ budget` holds and sharding
    /// can only make a bound slightly tighter, never looser. The cost is skew: a hub refuses when *a
    /// shard* fills, which per-process hash seeding makes unpredictable to a remote attacker (CWE-407)
    /// but also means the effective global cap is reached a little early. Pass `1` when a test needs
    /// every key on one lock and an exact budget.
    public init(limits: Limits = .default, shards: Int = 16) {
        self.limits = limits
        let subscriberPlan = Self.shardPlan(budget: limits.maxSubscribers, hint: shards)
        let topicPlan = Self.shardPlan(budget: limits.maxTopics, hint: shards)
        maxSubscribersPerShard = subscriberPlan.perShard
        maxTopicsPerShard = topicPlan.perShard
        subscribers = ShardedMutex(shards: subscriberPlan.shards) { _ in [:] }
        topics = ShardedMutex(shards: topicPlan.shards) { _ in [:] }
    }

    /// Registers a connection's `sink`, returning a token used to subscribe / unsubscribe / remove it.
    ///
    /// - Returns: the token, or `nil` when the subscriber budget is exhausted. `nil` is a refusal the
    ///   caller must act on — the server closes the freshly upgraded socket with `1013` — never a
    ///   condition to ignore.
    public func register(_ sink: @escaping Sink) -> UInt64? {
        let token = nextToken.wrappingAdd(1, ordering: .relaxed).newValue
        return subscribers.withLock(forKey: token) { shard in
            guard shard.count < maxSubscribersPerShard else {
                return nil
            }
            shard[token] = Subscriber(sink: sink)
            return token
        }
    }

    /// Subscribes `token` to `topic`, so a message published there reaches that connection.
    ///
    /// The subscriber shard is held across the topic-shard acquisition (the documented order), so the
    /// name check, both budget checks and both index updates are one atomic step: there is no window
    /// where the reverse index and the topic table disagree, and so nothing to roll back on refusal.
    ///
    /// Idempotent — re-subscribing to a topic already held is ``Subscription/admitted`` and consumes
    /// no budget, because that subscription is not a new allocation.
    @discardableResult
    public func subscribe(_ token: UInt64, to topic: String) -> Subscription {
        if let refusal = refusal(forTopicName: topic) {
            return .refused(refusal)
        }
        return subscribers.withLock(forKey: token) { shard in
            guard var subscriber = shard[token] else {
                return .refused(.unknownToken)
            }
            let budget = limits.maxSubscriptionsPerConnection
            let alreadyHeld = subscriber.topics.contains(topic)
            guard alreadyHeld || subscriber.topics.count < budget else {
                return .refused(.connectionSubscriptionLimit)
            }
            let sink = subscriber.sink
            let admitted = topics.withLock(forKey: topic) { table in
                guard table[topic] != nil || table.count < maxTopicsPerShard else {
                    return false
                }
                table[topic, default: [:]][token] = sink
                return true
            }
            guard admitted else {
                return .refused(.topicLimit)
            }
            subscriber.topics.insert(topic)
            shard[token] = subscriber
            return .admitted
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
    ///
    /// Snapshot under the lock, deliver outside it. The snapshot costs one array allocation per
    /// publish, which buys the property that a slow, blocking, or hub-re-entrant sink cannot stall an
    /// unrelated topic — see the type's *Delivery is not atomic with membership* note for what the
    /// snapshot deliberately does **not** promise.
    public func publish(_ message: WebSocketMessage, to topic: String) {
        let sinks = topics.withLock(forKey: topic) { table in
            table[topic].map { Array($0.values) } ?? []
        }
        for sink in sinks {
            sink(message)
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

    /// The refusal `topic` earns, or `nil` when the name is acceptable.
    ///
    /// VCHAR only (`%x21-7E`, RFC 5234 §B.1): no control octets, no space, no non-ASCII. A hub topic
    /// is an identifier the server logs, counts and compares — not free text. Checked before any
    /// budget is touched, so a malformed name cannot consume a connection's subscription budget.
    private func refusal(forTopicName topic: String) -> Refusal? {
        let octets = topic.utf8
        guard !octets.isEmpty else {
            return .emptyTopicName
        }
        guard octets.count <= limits.maxTopicNameLength else {
            return .topicNameTooLong
        }
        guard !octets.contains(where: { $0 < 0x21 || $0 > 0x7E }) else {
            return .topicNameNotVisibleASCII
        }
        return nil
    }

    /// Splits `budget` across a power-of-two shard count so the global bound stays hard.
    ///
    /// The count is clamped to `budget` (so every shard of a non-empty partition gets at least one
    /// entry) and rounded *down* to a power of two, which makes `shards × perShard ≤ budget`. Rounding
    /// *up* instead — what ``ShardedMutex`` does to its own hint — would let the partitioned total
    /// exceed the requested cap, i.e. would quietly unbound the bound.
    private static func shardPlan(budget: Int, hint: Int) -> (shards: Int, perShard: Int) {
        let requested = max(1, min(hint, max(1, budget)))
        let shards = 1 << (Int.bitWidth - 1 - requested.leadingZeroBitCount)
        return (shards, max(1, max(1, budget) / shards))
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
