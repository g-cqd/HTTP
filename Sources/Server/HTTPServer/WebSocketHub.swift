//
//  WebSocketHub.swift
//  HTTPServer
//
//  A topic-based publish/subscribe hub for WebSocket connections (RFC 6455): a connection subscribes to
//  topics, and a published ``WebSocketMessage`` is fanned out to every subscriber's sink — the
//  per-connection send channel the server drives. An `actor`, so concurrent connections register,
//  subscribe, and publish race-free. The server registers a sink when a hub-backed WebSocket upgrades and
//  removes it on disconnect; a handler publishes via the hub it captured (`await hub.publish(…, to:)`).
//

public import WebSocket

/// A topic fan-out hub for WebSocket connections — subscribe a connection's sink, publish to a topic.
public actor WebSocketHub {
    /// A per-connection delivery channel: a closure that sends one ``WebSocketMessage`` to a connection.
    public typealias Sink = @Sendable (WebSocketMessage) -> Void

    private var nextToken: UInt64 = 0
    private var sinks: [UInt64: Sink] = [:]
    private var topics: [String: Set<UInt64>] = [:]

    /// Creates an empty hub.
    public init() {
        // No state to seed.
    }

    /// Registers a connection's `sink`, returning a token used to subscribe / unsubscribe / remove it.
    public func register(_ sink: @escaping Sink) -> UInt64 {
        nextToken += 1
        sinks[nextToken] = sink
        return nextToken
    }

    /// Subscribes `token` to `topic`, so a message published there reaches that connection.
    public func subscribe(_ token: UInt64, to topic: String) {
        topics[topic, default: []].insert(token)
    }

    /// Unsubscribes `token` from `topic`.
    public func unsubscribe(_ token: UInt64, from topic: String) {
        topics[topic]?.remove(token)
        if topics[topic]?.isEmpty == true {
            topics[topic] = nil
        }
    }

    /// Removes `token` entirely on disconnect: drops its sink and every subscription it held.
    public func remove(_ token: UInt64) {
        sinks[token] = nil
        for topic in Array(topics.keys) {
            topics[topic]?.remove(token)
            if topics[topic]?.isEmpty == true {
                topics[topic] = nil
            }
        }
    }

    /// Publishes `message` to every connection subscribed to `topic` (RFC 6455 §5.6 fan-out).
    public func publish(_ message: WebSocketMessage, to topic: String) {
        guard let tokens = topics[topic] else {
            return
        }
        for token in tokens {
            sinks[token]?(message)
        }
    }

    /// The number of connections currently subscribed to `topic` (for metrics and tests).
    public func subscriberCount(of topic: String) -> Int {
        topics[topic]?.count ?? 0
    }
}
