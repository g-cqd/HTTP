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

    /// One of the three calls that `PortableTLSEngine` classifies through `SSL_get_error`.
    enum ClassifiedTLSCall: String, CaseIterable, Sendable, CustomStringConvertible {
        /// `PortableTLSEngine.acceptHandshake()` — `SSL_accept`.
        case acceptHandshake = "SSL_accept"
        /// `PortableTLSEngine.decrypt(ceiling:into:)` — `SSL_read`.
        case decrypt = "SSL_read"
        /// `PortableTLSEngine.encrypt(_:from:)` — `SSL_write`.
        case encrypt = "SSL_write"

        var description: String { rawValue }
    }

#endif
