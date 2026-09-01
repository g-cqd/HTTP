//
//  UnleasedTransportConnection.swift
//  HTTPTransport
//
//  The opt-in that carries the two ADAPTING ``TransportConnection`` defaults — the appending receive
//  and the copying `sendFile` — so that neither can be reached by inheritance.
//
//  Both defaults are written for a connection that owns nothing across a suspension point. Both are
//  wrong for one that does, in the same way and for the same reason: they compose a LOGICAL operation
//  out of several gated calls, so the direction is free in the gaps between them. That is not an
//  abstract concern here. The chunked `sendFile` default, inherited by ``PortableTLSConnection``,
//  released the outbound lease once per 64 KiB chunk and let a concurrent sender write its octets into
//  the middle of a file body; it was fixed by an override, and the override is only load-bearing for
//  as long as somebody remembers to write it.
//
//  So the defaults moved off ``TransportConnection`` and onto this refinement. Nothing about the two
//  implementations changed — what changed is that a conformer now gets them by SAYING it has no lease,
//  and a new backbone that says nothing gets a compile error naming the requirement it has to answer
//  rather than a silently narrowed ownership span.
//
//  This is not the `~Copyable, ~Escapable` capability token that was prototyped and declined (see
//  ``DirectionOwner``'s header): no value crosses a boundary here, so nothing has to survive the
//  escaping re-arm callbacks that made the token unworkable on the send direction. The two ideas are
//  orthogonal — that one was about the calls INSIDE an owned operation, this one is about which
//  operations a type inherits at all.
//
//  Standards: CWE-1188 (insecure default initialization of a resource) as the class — a default whose
//  correctness depends on a property of the conformer that nothing checks.
//

/// A ``TransportConnection`` that owns no cross-suspension lease on either direction.
///
/// Conform to this to inherit the two adapting defaults: ``receive(into:maxLength:)``, which reads one
/// chunk through ``TransportConnection/receive(maxLength:)`` and appends it, and
/// ``sendFile(descriptor:offset:length:)``, which `pread`s into a bounded scratch and sends each chunk.
/// Both compose a logical operation out of several gated calls, which is sound exactly when there is no
/// lease to release between them: Network.framework hands back its own `Data` and serializes nothing of
/// its own, and the in-memory fakes have no descriptor to own.
///
/// A backbone that DOES serialize a direction across suspension points — the four POSIX backbones with
/// their ``DirectionOwner``, the portable TLS connection with its two `AsyncExclusion` pumps — must not
/// conform, and must implement both itself so the lease spans the whole operation. Declining to conform
/// is not a chore: it is the statement, and the compiler will insist on it.
public protocol UnleasedTransportConnection: TransportConnection {}

extension UnleasedTransportConnection {
    /// Reads one chunk via ``TransportConnection/receive(maxLength:)`` and appends it to `buffer`,
    /// returning the count appended (`0` at EOF).
    ///
    /// Behaviour-identical to a `receive` followed by an `append`, and identical to what conformers
    /// inherited when this lived on ``TransportConnection`` itself. The append lands after that call
    /// has returned, which is precisely why this is not inheritable by a leased backbone: the chunk is
    /// an owned array, so nothing can be corrupted by copying it out late, but the lease the syscall
    /// ran under is already gone by then. A leased backbone that took this would be running two
    /// acquisitions where its own contract claims one operation — and its `assertInboundLeased`
    /// could not see it, because the append is here rather than in any code that backbone owns.
    ///
    /// It also allocates a chunk per read, which is the cost ``TransportConnection/receive(into:maxLength:)``
    /// exists to avoid; a conformer that can read straight into `buffer` should.
    public func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        guard let chunk = try await receive(maxLength: maxLength), !chunk.isEmpty else {
            return 0
        }
        buffer.append(contentsOf: chunk)
        return chunk.count
    }
}
