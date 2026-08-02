//
//  PortableTLSErrorQueueTests.swift
//  HTTPTransportTests
//
//  `SSL_get_error` consults BoringSSL's error queue BEFORE it looks at the session's own state, and
//  `err.h` is explicit that the queue is "for the current thread" — per-THREAD, not per-`SSL`. On the
//  face of it, a stale entry left on a pooled thread by a DIFFERENT connection therefore turns a
//  would-be `SSL_ERROR_WANT_READ` into a fatal `SSL_ERROR_SSL`, and a healthy keep-alive session is
//  dropped with an error it never committed. `ssl_lib.cc:1180`:
//
//      uint32_t err = ERR_peek_error();
//      if (err != 0) {
//        if (ERR_GET_LIB(err) == ERR_LIB_SYS) { return SSL_ERROR_SYSCALL; }
//        return SSL_ERROR_SSL;
//      }
//      ...
//      switch (ssl->s3->rwstate) {
//
//  That reading is why `PortableTLSEngine` calls `ERR_clear_error()` before each of `SSL_accept`,
//  `SSL_read` and `SSL_write`, and why three attempts to write a regression test for it — an in-task
//  poison, an executor preference, and an executor preference behind a `Task.yield()` — all passed
//  with the fix REVERTED and were deleted rather than shipped. The conclusion drawn then was that the
//  cooperative pool offers no way to pin the poison and the later `SSL_read` to one thread.
//
//  ## That conclusion was wrong, and this file is what corrects it
//
//  A fourth attempt does not race at all: `PortableTLSEngine` is synchronous and internal, and
//  `ERR_put_error` poisons THIS thread's queue with no scheduling involved. One thread, one poison,
//  one call, one classification — and it STILL passes with the fix reverted. It passes because in the
//  vendored BoringSSL there is nothing left to observe: every one of the three entry points begins by
//  clearing the queue itself (`ssl_lib.cc`).
//
//      void ssl_reset_error_state(SSL *ssl) {          // :79
//        // Functions which use |SSL_get_error| must reset I/O and error state on entry.
//        ssl->s3->rwstate = SSL_ERROR_NONE;
//        ERR_clear_error();
//        ERR_clear_system_error();
//      }
//
//  `SSL_do_handshake` (:706, and `SSL_accept` is a two-line wrapper over it at :746), `ssl_read_impl`
//  (:792, reached from `SSL_read` via `SSL_peek`), and `SSL_write` (:932) each open with that call.
//  So a neighbour's entry cannot survive into any of the three classifications, whether or not the
//  engine clears first. The three deleted tests asserted nothing for a much simpler reason than
//  scheduling.
//
//  This leaves `clearThreadErrorQueue()` as defence in depth rather than a load-bearing fix, and it is
//  worth keeping on those terms: ADR 0004 reached vendored BoringSSL only at Phase 6, and system
//  OpenSSL — which `SSL_read` does NOT clear for you — is the configuration the portable backbone
//  started from and could return to.
//
//  ## What is therefore pinned here
//
//  1. The PREMISE, at the library. Poison the queue, call the raw `SSL_*`, and assert the queue is
//     empty and the classification is `SSL_ERROR_WANT_READ`. This is the test that can go red: it does
//     so exactly when a BoringSSL bump stops clearing for us, which is the moment
//     `clearThreadErrorQueue()` stops being redundant and starts being the only thing holding the
//     line. That is a better guard than one pinned to a line of our own code that currently changes
//     nothing.
//  2. The CONTRACT, at the engine. A poisoned queue never becomes this session's failure, through the
//     real classification path, for all three calls. Stated as an outcome rather than a mechanism, so
//     it stays true and stays meaningful under either owner of the clear.
//
//  Honest limit: neither test fails if `clearThreadErrorQueue()` is deleted today. Verified, not
//  assumed — see the commit message for the mutation output. The field report this began with
//  (`SSL_read error 1` carrying `PEER_DID_NOT_RETURN_A_CERTIFICATE`, ~1 run in 12) is therefore NOT
//  explained by a stale pre-call queue on this library, and its real cause is still open.
//
//  Standards: BoringSSL `include/openssl/ssl.h` (`SSL_get_error`, `SSL_ERROR_SSL`) and
//  `include/openssl/err.h` (`ERR_clear_error`, "clears the error queue for the current thread").
//  CWE-393 (return of wrong status code) — a retryable condition reported as fatal; CWE-488 (exposure
//  of data element to wrong session) in the diagnostic sense. TLS 1.3 per RFC 8446.
//
//  Gated `#if canImport(CHTTPBoringSSLShims)`, so it compiles to nothing unless the build opted in
//  with `HTTP_PORTABLE_TLS=1`.
//

#if canImport(CHTTPBoringSSLShims)

    import CHTTPBoringSSL
    import CHTTPBoringSSLShims
    import Testing

    @testable import HTTPTransport

    @Suite("Portable TLS — the per-thread error queue does not reach a classification")
    struct PortableTLSErrorQueueTests {
        // MARK: - The premise, at the library

        @Test(
            "BoringSSL empties the thread's error queue on entry to each classified call",
            arguments: ClassifiedTLSCall.allCases
        )
        func libraryClearsTheQueueItself(_ call: ClassifiedTLSCall) throws {
            let session = try Self.makeAcceptStateSession()
            defer {
                CHTTPBoringSSL_SSL_free(session)
                CHTTPBoringSSL_ERR_clear_error()  // leave the thread as clean as we found it
            }
            Self.poison()

            let result = Self.performRaw(call, on: session)
            #expect(result <= 0, "the call was expected to wait for the peer, not to succeed")
            // The load-bearing observation. If a future BoringSSL stops calling
            // `ssl_reset_error_state` on entry, the poison is still here and this goes red — which is
            // precisely when `PortableTLSEngine.clearThreadErrorQueue()` becomes load-bearing.
            #expect(
                CHTTPBoringSSL_ERR_peek_error() == 0,
                "\(call) left a neighbour's error on the queue for SSL_get_error to read"
            )
            #expect(CHTTPBoringSSL_SSL_get_error(session, result) == SSL_ERROR_WANT_READ)
        }

        // MARK: - The contract, at the engine

        @Test(
            "a neighbour's queued error is never classified as this session's failure",
            arguments: ClassifiedTLSCall.allCases
        )
        func poisonedQueueDoesNotFailAHealthyCall(_ call: ClassifiedTLSCall) throws {
            var engine = try Self.makeAcceptStateEngine()
            defer {
                engine.release()
                CHTTPBoringSSL_ERR_clear_error()
            }
            Self.poison()
            #expect(
                CHTTPBoringSSL_ERR_peek_error() != 0,
                "the queue was not actually poisoned, so this asserts nothing"
            )

            let outcome = Self.perform(call, on: &engine)
            // Nothing has been fed to the read BIO, so every one of the three is waiting on the peer's
            // first flight. `.failed(1)` here would be `SSL_ERROR_SSL` — the neighbour's error,
            // wearing this session's name.
            guard case .wantRead = outcome else {
                Issue.record("\(call) classified a healthy wait as \(outcome)")
                return
            }
        }

        @Test(
            "the same call on a clean queue reaches the same verdict — the control",
            arguments: ClassifiedTLSCall.allCases
        )
        func cleanQueueClassifiesTheSameWay(_ call: ClassifiedTLSCall) throws {
            var engine = try Self.makeAcceptStateEngine()
            defer { engine.release() }
            CHTTPBoringSSL_ERR_clear_error()
            // Without this, a `.wantRead` above could be read as "this call never consults the queue"
            // rather than "the queue was empty by the time it did"; with it, the only variable left
            // between the two tests is the poison.
            guard case .wantRead = Self.perform(call, on: &engine) else {
                Issue.record("\(call) does not wait for the peer on a clean queue")
                return
            }
        }

        // MARK: - Fixture

        /// Puts the exact entry the mutual-TLS `.required` negative test leaves behind on this
        /// thread's queue: library 16 (`ERR_LIB_SSL`), reason 192 — together the `error:100000c0` of
        /// the field report.
        ///
        /// Deliberately not `ERR_LIB_SYS`, which `SSL_get_error` maps to `SSL_ERROR_SYSCALL` instead
        /// and would exercise a different arm.
        private static func poison() {
            CHTTPBoringSSL_ERR_put_error(
                Int32(ERR_LIB_SSL),
                0,
                Int32(SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE),
                #file,
                UInt32(#line)
            )
        }

        /// Runs `call` against `engine` and returns what it classified.
        private static func perform(
            _ call: ClassifiedTLSCall,
            on engine: inout PortableTLSEngine
        ) -> PortableTLSEngine.Outcome {
            switch call {
                case .acceptHandshake:
                    return engine.acceptHandshake()
                case .decrypt:
                    var sink: [UInt8] = []
                    return engine.decrypt(ceiling: 4_096, into: &sink)
                case .encrypt:
                    return engine.encrypt(Array("ping".utf8), from: 0)
            }
        }

        /// Runs the `SSL_*` entry point behind `call` directly, bypassing the engine.
        private static func performRaw(_ call: ClassifiedTLSCall, on ssl: OpaquePointer) -> Int32 {
            var scratch = [UInt8](repeating: 0, count: 64)
            switch call {
                case .acceptHandshake:
                    return CHTTPBoringSSL_SSL_accept(ssl)
                case .decrypt:
                    return scratch.withUnsafeMutableBytes { raw in
                        CHTTPBoringSSL_SSL_read(ssl, raw.baseAddress, Int32(raw.count))
                    }
                case .encrypt:
                    return scratch.withUnsafeBytes { raw in
                        CHTTPBoringSSL_SSL_write(ssl, raw.baseAddress, Int32(raw.count))
                    }
            }
        }

        /// A server-side engine in accept state over two empty memory BIOs — no socket, no peer.
        private static func makeAcceptStateEngine() throws -> PortableTLSEngine {
            let ssl = try makeAcceptStateSession()
            let readBIO = try #require(CHTTPBoringSSL_SSL_get_rbio(ssl))
            let writeBIO = try #require(CHTTPBoringSSL_SSL_get_wbio(ssl))
            return PortableTLSEngine(ssl: ssl, readBIO: readBIO, writeBIO: writeBIO)
        }

        /// A server `SSL` in accept state over two empty memory BIOs.
        ///
        /// Empty on purpose: with nothing to read, all three classified calls are waiting on the
        /// peer's first flight, which is precisely the `SSL_ERROR_WANT_READ` a stale queue entry would
        /// turn into a fatal error. The caller owns the `SSL` — `SSL_free` releases both BIOs with it.
        private static func makeAcceptStateSession() throws -> OpaquePointer {
            let identity = try DevTLSIdentity.selfSigned()
            let context = try #require(
                CHTTPBoringSSL_SSL_CTX_new(CHTTPBoringSSL_TLS_server_method()))
            // The `SSL` retains the context, so dropping our reference here leaves exactly one owner.
            defer { CHTTPBoringSSL_SSL_CTX_free(context) }
            #expect(CHTTPBoringSSLShims_set_min_proto_version(context, Int32(TLS1_3_VERSION)) == 1)
            let loaded = identity.pkcs12.withUnsafeBufferPointer { buffer in
                CHTTPBoringSSLShims_use_pkcs12(
                    context, buffer.baseAddress, Int32(buffer.count), identity.passphrase
                )
            }
            #expect(loaded == 1)

            let ssl = try #require(CHTTPBoringSSL_SSL_new(context))
            // `SSL_set_bio` takes ownership of both, so `SSL_free` frees them too.
            let readBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            let writeBIO = try #require(CHTTPBoringSSL_BIO_new(CHTTPBoringSSL_BIO_s_mem()))
            CHTTPBoringSSL_SSL_set_bio(ssl, readBIO, writeBIO)
            CHTTPBoringSSL_SSL_set_accept_state(ssl)
            return ssl
        }
    }

#endif
