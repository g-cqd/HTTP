//
//  ProbeContentEncoder.swift
//  HTTPServerTests
//
//  A ``StreamingContentEncoder`` fixture with an observable codec lifetime, so a test can assert *when*
//  the encoder's state was released without depending on a real backend's internals. Its capability is
//  chosen per instance: a nil ``lifetime`` makes ``makeStream()`` return nil, which is how a build whose
//  backend has no incremental form behaves.
//
//  The coding keeps every even-indexed octet of the body. Trivial, but deliberately two things at once:
//  it *shrinks*, which the buffered path requires before it will apply a coding at all, and it is
//  position-dependent, so a codec that lost track of where it was across chunk boundaries would produce
//  different octets than the one-shot form and the byte-identity expectations would catch it.
//

internal import Synchronization

@testable import HTTPServer

/// A content coding whose codec instances can be counted, and which can decline to stream.
struct ProbeContentEncoder: StreamingContentEncoder {
    /// The `Content-Encoding` token this fixture claims.
    let token: String

    /// The lifetime ledger its codecs report to, or nil to decline streaming entirely.
    let lifetime: Lifetime?

    /// Counts codec instances that have been created and not yet released.
    final class Lifetime: Sendable {
        private let live = Mutex(0)

        deinit {
            // No teardown beyond ARC; the Mutex releases with the instance.
        }

        /// How many codecs are still holding state.
        var liveCount: Int {
            live.withLock(\.self)
        }

        /// Records a codec taking state.
        func opened() {
            live.withLock { $0 += 1 }
        }

        /// Records a codec giving its state back.
        func closed() {
            live.withLock { $0 -= 1 }
        }
    }

    /// Every even-indexed octet of `body` — see the file note for why the coding is shaped this way.
    static func coded(_ body: some Collection<UInt8>, from offset: Int) -> [UInt8] {
        body.enumerated()
            .compactMap { (offset + $0.offset).isMultiple(of: 2) ? $0.element : nil }
    }

    func encode(_ body: [UInt8]) -> [UInt8]? {
        guard !body.isEmpty else {
            return nil
        }
        return Self.coded(body, from: 0)
    }

    func makeStream() -> (any ContentEncoderStream)? {
        guard let lifetime else {
            return nil
        }
        return Codec(lifetime)
    }

    /// One probe encode: the same coding applied chunk by chunk, with its existence recorded.
    private final class Codec: ContentEncoderStream {
        private let lifetime: Lifetime
        private var finished = false

        /// How many octets have been consumed, so the coding's parity survives a chunk boundary.
        private var offset = 0

        init(_ lifetime: Lifetime) {
            self.lifetime = lifetime
            lifetime.opened()
        }

        deinit {
            lifetime.closed()
        }

        func update(_ input: [UInt8]) throws(ContentEncodingError) -> [UInt8] {
            guard !finished else {
                throw .streamFinished
            }
            let coded = ProbeContentEncoder.coded(input, from: offset)
            offset += input.count
            return coded
        }

        func finish() throws(ContentEncodingError) -> [UInt8] {
            guard !finished else {
                throw .streamFinished
            }
            finished = true
            return []
        }
    }
}
