//
//  TLSCertificateRequest.swift
//  HTTPTLS
//
//  RFC 8446 §4.3.2 — the CertificateRequest encoder. In-handshake client authentication only
//  (this server never sends post-handshake CR), so the `certificate_request_context` "MUST be
//  zero length"; `signature_algorithms` is the one mandatory extension and the only one this
//  server offers — which is what makes the §4.4.2 entry-extension check in
//  ``TLSCertificateCodec`` a strict emptiness test.
//

/// The CertificateRequest encoder (RFC 8446 §4.3.2).
enum TLSCertificateRequestEncoder {
    /// Encodes the CertificateRequest: empty context, `signature_algorithms` only.
    static func certificateRequest(schemes: [TLSSignatureScheme]) -> [UInt8] {
        TLSHandshakeBuilder.message(.certificateRequest) { message in
            message.vector8 { _ in
                // certificate_request_context: zero length in the main handshake (§4.3.2)
            }
            message.vector16 { extensions in
                extensions.extensionField(.signatureAlgorithms) { body in
                    body.vector16 { list in
                        for scheme in schemes {
                            list.u16(scheme.rawValue)  // §4.2.3
                        }
                    }
                }
            }
        }
    }
}
