//
//  HealthTests.swift
//  HTTPObservabilityTests
//
//  Liveness vs readiness: `/healthz` stays 200, while `/readyz` flips 200 → 503 the moment the app marks
//  the `ReadinessProbe` draining — so a load balancer stops sending new work during a graceful shutdown
//  while in-flight requests finish.
//

import HTTPCore
import HTTPObservability
import HTTPServer
import Testing

@Suite("HTTPObservability — health probes")
struct HealthTests {
    @Test("/readyz flips 200 → 503 on drain; /healthz stays 200")
    func readyzFlipsOnDrain() async {
        let probe = ReadinessProbe()
        let router = Router {
            Health.healthz()
            Health.readyz(probe: probe)
        }

        #expect(await status(router, "/healthz") == 200)
        #expect(await status(router, "/readyz") == 200)

        probe.beginDraining()
        #expect(await status(router, "/readyz") == 503)
        #expect(await status(router, "/healthz") == 200)  // liveness is unaffected by draining
    }

    private func status(_ router: Router, _ path: String) async -> Int {
        let request = HTTPRequest(method: .get, scheme: "https", authority: "x", path: path)
        return Int(await router.respond(to: request, body: []).head.status.code)
    }
}
