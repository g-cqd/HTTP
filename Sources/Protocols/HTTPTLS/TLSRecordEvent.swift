//
//  TLSRecordEvent.swift
//  HTTPTLS
//
//  What the record layer surfaces per deprotected (or legitimately unprotected) record — the
//  seam Phase 3b's handshake machine consumes. Handshake events carry record-sized FRAGMENTS
//  (§5.1 lets messages be fragmented across and coalesced within records); reassembling them
//  into handshake messages is the handshake machine's job, so no message buffering happens here.
//

/// One record's content, surfaced by ``TLSRecordLayer/receive(_:)`` (RFC 8446 §5).
public enum TLSRecordEvent: Sendable, Equatable {
    /// A handshake-type record's content at the current read epoch (§4 messages, fragmented
    /// per §5.1 — the handshake machine reassembles).
    case handshake([UInt8])
    /// An application-data record's content (application epoch only; may be empty, §5.1).
    case applicationData([UInt8])
    /// An alert (§6) — `close_notify` ends the read direction; error alerts end the connection.
    case alert(TLSAlert)
}
