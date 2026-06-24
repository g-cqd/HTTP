//
//  Oracles.swift
//  HTTPTestSupport
//
//  Assertion oracles for the parsers: a typed-error assert that checks the error's *payload* (not just
//  "it threw something"), a round-trip identity assert (parse∘serialize), and a parity assert (two
//  independent computations agree). Every failure routes to `Issue.record` — the runner is never
//  trapped.
//

public import Testing

/// Asserts `expression` throws an `E`-typed error whose payload satisfies `predicate`.
///
/// A weak "it threw something" is never enough: the error must be the expected concrete type *and*
/// carry the expected case/associated value. Returns the caught error for inspection; routes every
/// failure (returned normally / wrong type / rejected payload) to `Issue.record`.
@discardableResult
public func expectThrows<T, E: Error>(
    _ expression: () throws -> T,
    sourceLocation: SourceLocation = #_sourceLocation,
    where predicate: (E) -> Bool
) -> E? {
    do {
        _ = try expression()
        Issue.record(
            "expected to throw \(E.self), but returned normally", sourceLocation: sourceLocation)
        return nil
    }
    catch let error as E {
        if predicate(error) { return error }
        Issue.record(
            "threw \(error) but its payload was rejected by the predicate",
            sourceLocation: sourceLocation)
        return error
    }
    catch {
        Issue.record("threw \(error) — not the expected \(E.self)", sourceLocation: sourceLocation)
        return nil
    }
}

/// The async form of ``expectThrows(_:sourceLocation:where:)``.
@discardableResult
public func expectThrows<T, E: Error>(
    _ expression: () async throws -> T,
    sourceLocation: SourceLocation = #_sourceLocation,
    where predicate: (E) -> Bool
) async -> E? {
    do {
        _ = try await expression()
        Issue.record(
            "expected to throw \(E.self), but returned normally", sourceLocation: sourceLocation)
        return nil
    }
    catch let error as E {
        if predicate(error) { return error }
        Issue.record(
            "threw \(error) but its payload was rejected by the predicate",
            sourceLocation: sourceLocation)
        return error
    }
    catch {
        Issue.record("threw \(error) — not the expected \(E.self)", sourceLocation: sourceLocation)
        return nil
    }
}

/// Asserts `value` survives a round trip unchanged (e.g. serialize→parse, encode→decode).
///
/// A thrown error or an unequal result is recorded; the runner is never trapped.
public func expectRoundTripIdentity<V: Equatable>(
    _ value: V,
    sourceLocation: SourceLocation = #_sourceLocation,
    via roundTrip: (V) throws -> V
) {
    do {
        let result = try roundTrip(value)
        if result != value {
            Issue.record(
                "round trip changed the value: \(value) → \(result)", sourceLocation: sourceLocation
            )
        }
    }
    catch {
        Issue.record("round trip threw: \(error)", sourceLocation: sourceLocation)
    }
}

/// Asserts two independent computations of the same value agree.
///
/// Records a labeled issue on divergence (e.g. a hand-decoded value vs. an engine-decoded one).
public func expectParity<V: Equatable>(
    _ lhs: V,
    _ rhs: V,
    _ label: String = "parity",
    sourceLocation: SourceLocation = #_sourceLocation
) {
    if lhs != rhs {
        Issue.record("\(label) mismatch: \(lhs) != \(rhs)", sourceLocation: sourceLocation)
    }
}
