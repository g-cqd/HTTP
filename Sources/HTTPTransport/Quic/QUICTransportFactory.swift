//
//  QUICTransportFactory.swift
//  HTTPTransport
//
//  The single QUIC-backbone selection point — the one place an `#available(macOS 26, iOS 26, *)` gate
//  lives (the codebase otherwise has none; this establishes the pattern). Two backbones implement
//  ``QUICServerTransport``:
//
//    • ``LegacyQUICTransport`` — the `NWConnectionGroup` callback API available at the macOS 15 floor.
//      It also runs on macOS 26 but is not selected there.
//    • The modern `NetworkConnection<QUIC>` typed-channel API (``ModernQUICTransport``), selected on
//      macOS 26+ / iOS 26+ — the native path.
//
//  Keeping the only `#available` here means every other file stays availability-free except the
//  `@available(macOS 26)` modern backbone itself; the package floor stays `macOS(.v15)`.
//

public import HTTPCore

/// Creates the ``QUICServerTransport`` backbone appropriate to the running OS (RFC 9114 over QUIC).
public enum QUICTransportFactory {
    /// The QUIC backbone for `configuration`, chosen by OS version.
    ///
    /// On macOS 26+ / iOS 26+ this is where the modern `NetworkConnection<QUIC>` backbone is selected;
    /// the legacy `NWConnectionGroup` backbone (which also runs on macOS 26) is used otherwise and as
    /// the validated default across the support range.
    public static func make(
        _ configuration: TransportConfiguration,
        limits: HTTPLimits = .default
    ) -> any QUICServerTransport {
        if #available(macOS 26, iOS 26, *) {
            return ModernQUICTransport(configuration: configuration, limits: limits)
        }
        return LegacyQUICTransport(configuration: configuration, limits: limits)
    }
}
