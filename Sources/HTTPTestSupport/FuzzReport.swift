//
//  FuzzReport.swift
//  HTTPTestSupport
//
//  What a fuzz run observed. Reaching a report at all is the PASS signal — a trap aborts the process
//  before the loop can return one.
//

/// What a fuzz run observed.
///
/// Reaching a report at all is the PASS signal — a trap aborts the process before the loop can
/// return one.
public struct FuzzReport: Sendable, Equatable {
    /// The number of iterations run.
    public let iterations: Int
    /// The total number of edits applied across all iterations.
    public let totalEdits: Int
}
