//
//  TLSHandshakeCoalescer.swift
//  HTTPTLS
//
//  RFC 8446 §5.1 — handshake-message reassembly over ``TLSRecordEvent/handshake(_:)``
//  fragments: messages may span records and share records, in both directions, so the record
//  layer surfaces raw fragments and this type restores §4 message boundaries. The declared
//  `uint24` length is capped BEFORE its body is awaited (a length lie cannot grow the buffer
//  past the cap), and ``hasPartialMessage`` scopes §5.1's no-interleaving rule ("if a handshake
//  message is split over two or more records, there MUST NOT be any other records between
//  them") for the machine to enforce.
//

/// Reassembles §4 handshake messages from §5.1 record-sized fragments.
struct TLSHandshakeCoalescer {
    /// One reassembled handshake message: its type, its body, and the raw framed octets
    /// (header + body) that the §4.4.1 transcript must absorb.
    struct Message {
        /// The message type (§4).
        let type: TLSHandshakeType
        /// The message body (everything after the 4-octet header), sliced from `raw`.
        var body: ArraySlice<UInt8> {
            raw[4...]
        }
        /// The full framed message — what `Transcript-Hash` consumes (§4.4.1).
        let raw: [UInt8]
    }

    /// The §4 message header: type (1) + `uint24` length (3).
    private static let headerLength = 4

    /// Fragments accumulated toward the next message boundary.
    private var buffer: [UInt8] = []
    /// The reassembly cap: a declared length beyond this is fatal (flood protection).
    let maximumMessageLength: Int

    /// Creates a coalescer with the given reassembly cap.
    init(maximumMessageLength: Int) {
        self.maximumMessageLength = maximumMessageLength
    }

    /// Whether a message is mid-reassembly — the §5.1 no-interleaving window.
    var hasPartialMessage: Bool {
        !buffer.isEmpty
    }

    /// Absorbs one record's handshake fragment.
    mutating func feed(_ fragment: [UInt8]) {
        buffer.append(contentsOf: fragment)
    }

    /// Extracts the next complete message, or nil when more octets are needed.
    mutating func next() throws(TLSHandshakeError) -> Message? {
        guard buffer.count >= Self.headerLength else {
            return nil
        }
        guard let type = TLSHandshakeType(rawValue: buffer[0]) else {
            throw .unknownHandshakeType(buffer[0])  // §6.2 unexpected_message
        }
        let declared = Int(buffer[1]) << 16 | Int(buffer[2]) << 8 | Int(buffer[3])
        guard declared <= maximumMessageLength else {
            throw .messageTooLarge(declared: declared, limit: maximumMessageLength)
        }
        let total = Self.headerLength + declared
        guard buffer.count >= total else {
            return nil
        }
        let raw = [UInt8](buffer[0 ..< total])
        buffer.removeFirst(total)
        return Message(type: type, raw: raw)
    }
}
