//
//  HTTPServer+DeadlineClock.swift
//  HTTPServer
//
//  The two edges between the injected `Clock` and the concrete `Duration` keys a ``DeadlineWheel``
//  orders by.
//
//  The wheel is deliberately NOT generic over `C.Instant`: an associated type is address-only in the
//  unspecialized generic code `HTTPServer<C: Clock>` compiles to, which made every heap `swapAt` and
//  every `Optional<Instant>` temporary a heap allocation — 24 of them per re-arm, around every read.
//  Everything the wheel needs is an ordering, and elapsed `Duration` since a fixed epoch is an
//  order-isomorphic concrete stand-in for the instant. Converting here keeps that trade in one place.
//

extension HTTPServer {
    /// The wheel key for a deadline `budget` from now — elapsed time since the server's epoch.
    ///
    /// Monotonic in the clock, so ordering keys orders instants. Called around every read, and free of
    /// allocation because `Duration` is concrete.
    func deadlineKey(after budget: Duration) -> Duration {
        epoch.duration(to: clock.now) + budget
    }

    /// The wheel key for "now" — what the watchdog fires against.
    var deadlineNow: Duration { epoch.duration(to: clock.now) }

    /// The instant a wheel key names, so the watchdog can `clock.sleep(until:)` it.
    func deadlineInstant(for key: Duration) -> C.Instant {
        epoch.advanced(by: key)
    }
}
