//
//  RequestContext.swift
//  HTTPServer
//
//  The per-request connection context threaded through the responder seam alongside the request and
//  its body. A request carries more than its head + bytes: the verified connection metadata it arrived
//  on (peer, TLS subject, ALPN, connection id — RFC 9110 §7.3, RFC 7301, RFC 9001), the matched route's
//  captured path parameters (RFC 3986 §3.3), an optional correlation id, an optional deadline, and a
//  type-keyed storage bag that middleware uses to hand typed data (an authenticated user, a pooled DB
//  handle, a trace span) to the handler. It is a `struct` so the hot path stays allocation-lean — the
//  metadata is all value types and the storage bag is a *lazily* allocated copy-on-write box, so a
//  request that touches no storage adds zero allocations over the previous `[UInt8]`-only seam.
//

internal import HTTPCore
public import HTTPTransport

/// The per-request context the server threads through the responder seam (peer, TLS, route parameters,
/// correlation id, deadline, and a typed storage bag).
///
/// The server builds it once at the protocol-engine dispatch point — from the ``TransportConnection``
/// (HTTP/1.1, HTTP/2) or ``QUICConnection`` (HTTP/3) the request arrived on — and passes it to the
/// responder. Middleware may enrich it (most commonly via ``subscript(_:)``) and pass the modified value
/// down the chain; because it is a value type, an enrichment is visible only to the handlers below it.
public struct RequestContext: Sendable {
    /// Verified, server-asserted metadata about the connection a request arrived on — the context the
    /// previous seam dropped (it only stamped the TLS subject onto a header).
    public struct Connection: Sendable {
        /// The peer's network address, or `nil` for a synthetic context (tests, direct invocation).
        public var peer: TransportAddress?

        /// The subject of the peer's verified client certificate (mutual TLS, RFC 9001), or `nil` when
        /// none was presented.
        ///
        /// Server-asserted: captured from the verified TLS handshake, never from a client-supplied
        /// header, so a peer cannot spoof it (the canonical replacement for the former
        /// `X-Client-Cert-Subject` request-header stamp).
        public var tlsPeerSubject: String?

        /// Whether transport-level encryption (TLS / QUIC) is active on this connection.
        public var isSecure: Bool

        /// The ALPN-negotiated application protocol (RFC 7301) — e.g. `"h2"`, `"http/1.1"`, `"h3"` — or
        /// `nil` over cleartext or before the handshake settles.
        public var negotiatedApplicationProtocol: String?

        /// The transport's stable identifier for this connection, or `nil` when not applicable (HTTP/3
        /// multiplexes over a QUIC connection that exposes no such id).
        public var id: TransportConnectionID?

        /// Creates connection metadata — all defaulted to the cleartext/unknown case for synthetic
        /// contexts.
        public init(
            peer: TransportAddress? = nil,
            tlsPeerSubject: String? = nil,
            isSecure: Bool = false,
            negotiatedApplicationProtocol: String? = nil,
            id: TransportConnectionID? = nil
        ) {
            self.peer = peer
            self.tlsPeerSubject = tlsPeerSubject
            self.isSecure = isSecure
            self.negotiatedApplicationProtocol = negotiatedApplicationProtocol
            self.id = id
        }
    }

    /// Verified metadata about the connection a request arrived on.
    public var connection: Connection

    /// A correlation id for logging and tracing: the inbound `X-Request-ID` when a client or front proxy
    /// supplied a syntactically valid one, otherwise `nil`.
    ///
    /// The server does not mint one on the hot path (an unconditional per-request allocation the codebase
    /// avoids); add ``RequestIDMiddleware`` to guarantee an id — it mints a fresh one when none is present
    /// and writes it back here for downstream handlers and the access log.
    public var id: String?

    /// The path parameters the matched ``Route`` captured (e.g. `:id` in `/users/:id`).
    ///
    /// Empty until a ``Router`` matches a route, then set to that route's captures for the handlers below
    /// it — replacing the former `Route.currentParameters` task-local.
    public var parameters: RouteParameters

    /// An optional point in time by which the response should be produced.
    ///
    /// Carried here for handlers and a future timeout layer to honor; the engine does not enforce it on
    /// its own. Timed against the continuous clock.
    public var deadline: ContinuousClock.Instant?

    /// The lazily-allocated, copy-on-write storage bag (see ``subscript(_:)``).
    ///
    /// Defaults to a shared empty sentinel, so an unused bag costs no per-request allocation; the first
    /// write copies the sentinel into a fresh box (standard COW), and value semantics keep one request's
    /// writes from leaking sideways into another's context.
    private var storage: StorageBox

    /// Creates a context from its parts — all defaulted, so `RequestContext()` is a valid empty context
    /// for tests and direct responder invocation.
    public init(
        connection: Connection = Connection(),
        id: String? = nil,
        parameters: RouteParameters = RouteParameters(),
        deadline: ContinuousClock.Instant? = nil
    ) {
        self.connection = connection
        self.id = id
        self.parameters = parameters
        self.deadline = deadline
        self.storage = .empty
    }

    /// Builds the context for a request that arrived over a ``TransportConnection`` (HTTP/1.1, HTTP/2),
    /// copying its verified metadata and adopting any valid inbound `X-Request-ID`.
    init(connection: any TransportConnection, request: HTTPRequest) {
        self.init(
            connection: Connection(
                peer: connection.peer,
                tlsPeerSubject: connection.tlsPeerSubject,
                isSecure: connection.isSecure,
                negotiatedApplicationProtocol: connection.negotiatedApplicationProtocol,
                id: connection.id
            ),
            id: Self.inboundRequestID(request)
        )
    }

    /// Builds the context for a request that arrived over a ``QUICConnection`` (HTTP/3): QUIC is always
    /// encrypted, so `isSecure` is `true` and the protocol defaults to `"h3"`; the QUIC connection
    /// exposes no transport-connection id, so ``Connection/id`` is `nil`.
    init(quic: any QUICConnection, request: HTTPRequest) {
        self.init(
            connection: Connection(
                peer: quic.peer,
                tlsPeerSubject: quic.tlsPeerSubject,
                isSecure: true,
                negotiatedApplicationProtocol: quic.negotiatedApplicationProtocol ?? "h3"
            ),
            id: Self.inboundRequestID(request)
        )
    }

    /// Reads or writes the value middleware stored under `key` — a type-safe, per-request bag for
    /// passing data from a middleware to the handlers below it.
    ///
    /// The value type is fixed by the key's ``RequestStorageKey/Value``, so retrieval needs no cast.
    /// Writing `nil` removes the entry. Mutation is copy-on-write, so enriching a copy of the context
    /// (the usual `var context = context; context[K.self] = …; next.respond(…, context: context)` pattern)
    /// never disturbs the caller's value.
    public subscript<Key: RequestStorageKey>(_ key: Key.Type) -> Key.Value? {
        get { storage.value(for: key) }
        set {
            if !isKnownUniquelyReferenced(&storage) {
                storage = storage.copy()
            }
            storage.set(newValue, for: key)
        }
    }

    /// The inbound `X-Request-ID` when it is a safe correlation token (non-empty, bounded, visible
    /// ASCII), else `nil` — so a hostile value cannot smuggle control bytes into a log line.
    static func inboundRequestID(_ request: HTTPRequest) -> String? {
        guard let inbound = request.headerFields[.xRequestID],
            !inbound.isEmpty, inbound.count <= 200,
            inbound.utf8.allSatisfy({ (0x21 ... 0x7e).contains($0) })
        else {
            return nil
        }
        return inbound
    }

    /// The copy-on-write backing store for the typed bag.
    ///
    /// `@unchecked Sendable` is sound under the COW discipline ``subscript(_:)`` enforces: a
    /// non-uniquely-held box is copied before any mutation, so no two contexts ever mutate the same
    /// instance — the same reasoning that makes the standard library's value types `Sendable`.
    private final class StorageBox: @unchecked Sendable {
        private var values: [ObjectIdentifier: any Sendable]

        init(_ values: [ObjectIdentifier: any Sendable]) {
            self.values = values
        }

        deinit {
            // No teardown beyond ARC; the dictionary releases with the instance.
        }

        /// The shared empty sentinel every fresh context starts from — never mutated (the first write
        /// copies it), so sharing it across requests adds no per-request allocation.
        static let empty = StorageBox([:])

        /// A fresh, independently mutable copy (the write half of copy-on-write).
        func copy() -> StorageBox {
            StorageBox(values)
        }

        func value<Key: RequestStorageKey>(for key: Key.Type) -> Key.Value? {
            values[ObjectIdentifier(key)] as? Key.Value
        }

        func set<Key: RequestStorageKey>(_ newValue: Key.Value?, for key: Key.Type) {
            values[ObjectIdentifier(key)] = newValue
        }
    }
}
