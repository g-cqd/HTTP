import Testing
import X509

@Suite("Test PKI — certificate serials")
struct TestPKITests {
    @Test
    func `concurrent test certificates receive distinct nonzero serials`() async throws {
        let issuer = try TestPKI.certificateAuthority()
        let serials = try await withThrowingTaskGroup(of: Certificate.SerialNumber.self) { group in
            for index in 0 ..< 8 {
                group.addTask {
                    try TestPKI.issued(commonName: "leaf-\(index)", by: issuer).certificate
                        .serialNumber
                }
            }
            var result = Set<Certificate.SerialNumber>()
            for try await serial in group { result.insert(serial) }
            return result
        }
        #expect(serials.count == 8)
        #expect(!serials.contains(issuer.certificate.serialNumber))
        #expect(!serials.contains(Certificate.SerialNumber(0)))
    }
}
