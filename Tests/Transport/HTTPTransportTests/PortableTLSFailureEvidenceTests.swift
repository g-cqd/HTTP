//
//  PortableTLSFailureEvidenceTests.swift
//  HTTPTransportTests
//
//  A fatal TLS classification must carry its own evidence, because the evidence does not keep:
//  BoringSSL's error queue is per-thread and the NEXT classified call on the thread destroys it —
//  `err.h` ("ERR_get_error gets the packed error code for the least recent error and removes that
//  error from the queue"), and `ssl_lib.cc:79` (`ssl_reset_error_state` clears the whole queue on
//  entry to each of the three classified entry points). Whatever the queue held at the moment of an
//  `SSL_ERROR_SSL` exists exactly once, at the classification seam, and nowhere afterwards.
//
//  This suite pins that ``TLSFailureEvidence`` captures it there and that the capture survives into
//  the description the connection throws — the surface a field report actually records. Sits beside
//  `PortableTLSErrorQueueTests`, which pins the complementary premise (a stale PRE-call queue cannot
//  reach a classification on this library).
//
//  The deterministic fatal call: a server whose peer's first flight is HTTP plaintext. The record
//  layer rejects it before anything else — `s3_both.cc` (`tls_open_handshake`): a first flight
//  beginning `"GET "` is `OPENSSL_PUT_ERROR(SSL, SSL_R_HTTP_REQUEST)` and `ssl_open_record_error` —
//  so every classified call comes back `SSL_ERROR_SSL` with the library's own entry on the queue,
//  no scheduling and no poison-survival assumptions involved.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)` like the rest of the portable backbone.
//

#if canImport(CHTTPBoringSSLShims)

    import CHTTPBoringSSL
    import CHTTPBoringSSLShims
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS — a fatal classification carries its own evidence")
    struct PortableTLSFailureEvidenceTests {
        /// The identity every fixture engine is constructed with — asserted on below, so a match can
        /// only have come from the capture.
        private static let connectionID = TransportConnectionID(41)

        // MARK: - The capture itself

        @Test("capture renders the queued entry, the connection, and the thread — then drains")
        func captureRendersThePoisonedQueue() {
            defer { CHTTPBoringSSL_ERR_clear_error() }
            // The exact entry of the field report this hook exists for: library 16 (`ERR_LIB_SSL`),
            // reason `PEER_DID_NOT_RETURN_A_CERTIFICATE`.
            CHTTPBoringSSL_ERR_put_error(
                Int32(ERR_LIB_SSL),
                0,
                Int32(SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE),
                #file,
                UInt32(#line)
            )

            let evidence = TLSFailureEvidence.capture(
                status: SSL_ERROR_SSL,
                call: "SSL_read",
                connectionID: Self.connectionID
            )

            // The historical grep key first — the field report read "SSL_read error 1".
            #expect(evidence.description.contains("SSL_read error 1"))
            #expect(evidence.description.contains("PEER_DID_NOT_RETURN_A_CERTIFICATE"))
            #expect(evidence.description.contains("connection 41"))
            #expect(evidence.description.contains("thread "))
            #expect(
                CHTTPBoringSSL_ERR_peek_error() == 0,
                "capture must drain what it renders — a left-over entry would smear the next failure"
            )
        }

        @Test("capture is bounded — at most 8 entries drained, oldest first")
        func captureIsBounded() {
            defer { CHTTPBoringSSL_ERR_clear_error() }
            for _ in 0 ..< 12 {
                CHTTPBoringSSL_ERR_put_error(
                    Int32(ERR_LIB_SSL),
                    0,
                    Int32(SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE),
                    #file,
                    UInt32(#line)
                )
            }

            let evidence = TLSFailureEvidence.capture(
                status: SSL_ERROR_SSL,
                call: "SSL_read",
                connectionID: Self.connectionID
            )

            #expect(evidence.queueEntries.count == TLSFailureEvidence.queueEntryCeiling)
        }

        // MARK: - The seam, end to end

        @Test(
            "a fatal classification carries the queue entry, the connection, and the call",
            arguments: ClassifiedTLSCall.allCases
        )
        func classifiedFailureCarriesTheEvidence(_ call: ClassifiedTLSCall) throws {
            var engine = try Self.makeEngineFacingAnHTTPClient()
            defer {
                engine.release()
                CHTTPBoringSSL_ERR_clear_error()
            }

            let outcome = call.drive(&engine)
            guard case .failed(let evidence) = outcome else {
                Issue.record("\(call) did not classify the HTTP first flight as fatal: \(outcome)")
                return
            }
            #expect(evidence.status == SSL_ERROR_SSL)
            // Same shape as the field report ("SSL_read error 1"), for whichever call failed …
            #expect(evidence.description.contains("\(call) error \(SSL_ERROR_SSL)"))
            // … now carrying the queue entry the library put there, verbatim …
            #expect(evidence.description.contains("HTTP_REQUEST"))
            // … and the identity of the connection it belongs to.
            #expect(evidence.description.contains("connection 41"))
        }

        // MARK: - Fixture

        /// A server-side engine whose peer's first flight is already in the read BIO — and is HTTP
        /// plaintext, which the record layer rejects as `SSL_R_HTTP_REQUEST` before certificate
        /// selection, so no identity needs loading.
        private static func makeEngineFacingAnHTTPClient() throws -> PortableTLSEngine {
            let context = try #require(
                CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_server_method()))
            // The `SSL` retains the context, so dropping our reference here leaves exactly one owner.
            defer { CHTTPBoringSSL_SSL_CTX_free(context) }
            let ssl = try #require(CHTTPBoringSSL_SSL_new(context))
            // `SSL_set_bio` takes ownership of both, so `SSL_free` (via `release()`) frees them too.
            let readBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            let writeBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            CHTTPBoringSSL_SSL_set_bio(ssl, readBIO, writeBIO)
            CHTTPBoringSSL_SSL_set_accept_state(ssl)

            let flight = Array("GET / HTTP/1.1\r\n\r\n".utf8)
            let fed = flight.withUnsafeBytes { raw in
                CHTTPBoringSSL_BIO_write(readBIO, raw.baseAddress, Int32(raw.count))
            }
            #expect(fed == Int32(flight.count))

            return PortableTLSEngine(
                ssl: ssl,
                readBIO: readBIO,
                writeBIO: writeBIO,
                connectionID: connectionID
            )
        }
    }

#endif
