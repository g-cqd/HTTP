//
//  Health.swift
//  HTTPObservability
//
//  The Kubernetes-style health probes. `/healthz` is liveness — always 200 once the process is up, so an
//  orchestrator only restarts a truly wedged process. `/readyz` is readiness — 200 until the app begins
//  draining for a graceful shutdown (signalled through a ``ReadinessProbe``), then 503 so traffic drains
//  away while in-flight requests finish. Add the routes to your ``Router``.
//

internal import HTTPCore
public import HTTPServer

/// Builds the `/healthz` (liveness) and `/readyz` (readiness) routes.
public enum Health {
    /// A `/healthz` liveness route — always 200 while the process is running.
    public static func healthz(path: String = "/healthz") -> Route {
        Route.get(path) { _, _, _ in .text("ok\n") }
    }

    /// A `/readyz` readiness route — 200 while `probe` is ready, 503 once it is draining.
    public static func readyz(path: String = "/readyz", probe: ReadinessProbe) -> Route {
        Route.get(path) { _, _, _ in
            probe.isReady ? .text("ready\n") : .status(.serviceUnavailable)
        }
    }

    /// Both health routes (`/healthz` + `/readyz`) wired to `probe`.
    public static func routes(probe: ReadinessProbe) -> [Route] {
        [healthz(), readyz(probe: probe)]
    }
}
