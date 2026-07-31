//
//  SynthesizedUploadConnection.swift
//  HTTPTestSupport
//
//  A fake connection that *synthesizes* an arbitrarily large request as it is read, instead of holding
//  it. `FakeConnection` and ``DribblingConnection`` both retain their whole inbound array, so a test
//  that wants to prove the server streams a 256 MiB upload with bounded memory would allocate 256 MiB
//  in the harness — masking exactly the regression it guards (audit CR-F5 / addendum P0.4).
//
//  The upload is described as a script of segments — literal octets for framing, a generated run for
//  payload — and each `receive` materializes at most `maxLength` octets of the current segment. Peak
//  harness residency is therefore one read, whatever the nominal upload size.
//
//  ``receiveCount`` is the backpressure oracle: a test parks the handler and asserts the count stops
//  advancing, which is what "the producer suspended until the consumer took a chunk" looks like from
//  the wire side.
//

public import HTTPTransport

/// An in-memory ``TransportConnection`` that generates a large upload on demand rather than storing it.
public actor SynthesizedUploadConnection: TransportConnection {
    /// How the synthesized body is framed on the wire (RFC 9112 §6).
    public enum Framing: Sendable, Equatable {
        /// A `Content-Length` body: the octets follow the head directly.
        case contentLength
        /// A chunked transfer-coding body emitted in `chunkSize`-octet chunks (RFC 9112 §7.1).
        case chunked(chunkSize: Int)
    }

    /// One piece of the scripted wire image: either octets held verbatim (framing, which is small) or
    /// a run generated on demand (payload, which is not).
    private enum Segment: Sendable {
        case literal([UInt8])
        case fill(UInt8, count: Int)

        /// How many octets this segment contributes to the wire image.
        var octetCount: Int {
            switch self {
                case .literal(let bytes):
                    bytes.count
                case .fill(_, let octets):
                    octets
            }
        }
    }

    /// The connection's stable identifier.
    nonisolated public let id: TransportConnectionID

    /// The peer's address.
    nonisolated public let peer: TransportAddress

    /// How many times the server has called `receive` — the backpressure oracle.
    public private(set) var receiveCount = 0

    private let segments: [Segment]
    private var index = 0
    private var offset = 0
    private var output: [UInt8] = []

    /// Creates a connection that will emit `head`, then `bodyCount` octets framed per `framing`, then
    /// `tail` (a pipelined follow-up request, when one is wanted).
    ///
    /// Nothing the size of `bodyCount` is ever allocated: the payload run is materialized one read at
    /// a time. `head` must already declare the framing it is paired with — this type writes the
    /// chunk framing but not the header section, so a test states the exact request it means.
    public init(
        id: TransportConnectionID,
        peer: TransportAddress = TransportAddress(host: "synth", port: 0),
        head: [UInt8],
        bodyCount: Int,
        framing: Framing,
        fill: UInt8 = 0x41,
        tail: [UInt8] = []
    ) {
        self.id = id
        self.peer = peer
        var script: [Segment] = [.literal(head)]
        switch framing {
            case .contentLength:
                script.append(.fill(fill, count: bodyCount))
            case .chunked(let chunkSize):
                Self.appendChunks(bodyCount, chunkSize: chunkSize, fill: fill, to: &script)
        }
        if !tail.isEmpty {
            script.append(.literal(tail))
        }
        segments = script.filter { $0.octetCount > 0 }
    }

    /// Scripts `bodyCount` octets as chunked transfer-coding units of `chunkSize` (RFC 9112 §7.1).
    private static func appendChunks(
        _ bodyCount: Int, chunkSize: Int, fill: UInt8, to script: inout [Segment]
    ) {
        var remaining = bodyCount
        let size = max(1, chunkSize)
        while remaining > 0 {
            let take = min(size, remaining)
            script.append(.literal(Array(String(take, radix: 16).utf8) + [0x0D, 0x0A]))
            script.append(.fill(fill, count: take))
            script.append(.literal([0x0D, 0x0A]))
            remaining -= take
        }
        script.append(.literal(Array("0\r\n\r\n".utf8)))  // last-chunk + empty trailer section
    }

    /// Delivers up to `maxLength` octets of the scripted upload, or `nil` once it is exhausted.
    public func receive(maxLength: Int) async -> [UInt8]? {
        guard index < segments.count else {
            return nil
        }
        receiveCount += 1
        let segment = segments[index]
        let start = offset
        let take = min(max(maxLength, 0), segment.octetCount - start)
        guard take > 0 else {
            return []  // a non-positive read budget: report it as EOF rather than spinning
        }
        offset = start + take
        if offset == segment.octetCount {
            index += 1
            offset = 0
        }
        switch segment {
            case .literal(let bytes):
                return Array(bytes[start ..< start + take])
            case .fill(let byte, _):
                // The whole point: only the octets this read delivers are ever materialized.
                return [UInt8](repeating: byte, count: take)
        }
    }

    /// Records `bytes` as sent to the peer.
    public func send(_ bytes: [UInt8]) async {
        output.append(contentsOf: bytes)
    }

    /// A no-op for the in-memory connection.
    public func close() async {
        // no-op: the in-memory connection has nothing to tear down.
    }

    /// The bytes sent to the peer so far (test inspection).
    public func sentBytes() -> [UInt8] {
        output
    }

    /// Whether every scripted octet has been read — the desync check a truncation test needs.
    public var isDrained: Bool { index >= segments.count }
}
