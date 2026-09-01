//
//  TLSKeyScheduleError.swift
//  HTTPTLS
//
//  The key schedule's typed misuse failure. RFC 8446 §7.1 is a strict three-stage ladder
//  (early → handshake → master); asking a stage for a secret it does not own is a driver bug,
//  surfaced as a typed error rather than a trap so the connection fails closed.
//

/// A key-schedule misuse (RFC 8446 §7.1): a derivation requested outside its stage.
public enum TLSKeyScheduleError: Error, Sendable, Equatable {
    /// The requested derivation belongs to a §7.1 stage the schedule is not currently in.
    case wrongStage
}
