//
//  ClassifiedTLSCall.swift
//  HTTPTransportTests
//
//  The three `SSL_*` calls whose result `PortableTLSEngine` feeds to `SSL_get_error`, named so a
//  parameterized test can drive each one and the failure message says which.
//
//  These are exactly the three sites that must clear BoringSSL's per-thread error queue first — see
//  `PortableTLSErrorQueueTests` for what happens to the one that does not. Adding a fourth classified
//  call to the engine and not adding it here is the mistake this enum exists to make visible.
//

#if canImport(CHTTPBoringSSLShims)

    @testable import HTTPTransport

    /// One of the three calls that `PortableTLSEngine` classifies through `SSL_get_error`.
    enum ClassifiedTLSCall: String, CaseIterable, Sendable, CustomStringConvertible {
        /// `PortableTLSEngine.acceptHandshake()` — `SSL_accept`.
        case acceptHandshake = "SSL_accept"
        /// `PortableTLSEngine.decrypt(ceiling:into:)` — `SSL_read`.
        case decrypt = "SSL_read"
        /// `PortableTLSEngine.encrypt(_:from:)` — `SSL_write`.
        case encrypt = "SSL_write"

        var description: String { rawValue }

        /// Runs this call against `engine` and returns what the engine classified — shared by the
        /// error-queue and failure-evidence suites, so the two cannot drift on what "one call" is.
        func drive(_ engine: inout PortableTLSEngine) -> PortableTLSEngine.Outcome {
            switch self {
                case .acceptHandshake:
                    return engine.acceptHandshake()
                case .decrypt:
                    var sink: [UInt8] = []
                    return engine.decrypt(ceiling: 4_096, into: &sink)
                case .encrypt:
                    return engine.encrypt(Array("ping".utf8), from: 0)
            }
        }
    }

#endif
